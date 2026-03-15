"""
Dead-Letter Queue monitor for the pipeline worker.

Periodically checks the DLQ for failed pipeline messages and exposes
the queue depth as a Prometheus metric. Alerts are triggered via the
Prometheus alert rules when the DLQ exceeds a threshold.

Usage::

    from shared.common.dlq_monitor import DLQMonitor

    monitor = DLQMonitor()
    depth = monitor.check_depth()
    messages = monitor.peek_messages(limit=5)
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class DLQMonitor:
    """Monitor the SQS Dead-Letter Queue for failed pipeline messages.

    Args:
        dlq_url: SQS DLQ URL. Defaults to SQS_DLQ_URL env var.
        alert_threshold: Number of messages to trigger an alert.
    """

    def __init__(
        self,
        dlq_url: Optional[str] = None,
        alert_threshold: int = 10,
    ):
        self.dlq_url = dlq_url or os.getenv("SQS_DLQ_URL", "")
        self.alert_threshold = alert_threshold
        self._sqs_client = None

    def _get_sqs(self):
        """Lazy-init SQS client."""
        if self._sqs_client is None:
            try:
                from shared.common.sqs import SQSClient
                self._sqs_client = SQSClient()
            except Exception as exc:
                logger.error("Failed to create SQS client: %s", exc)
                raise
        return self._sqs_client

    def check_depth(self) -> int:
        """Check the approximate number of messages in the DLQ.

        Returns:
            Approximate message count.
        """
        if not self.dlq_url:
            logger.warning("SQS_DLQ_URL not configured — DLQ monitoring disabled")
            return 0

        try:
            import boto3
            region = os.getenv("AWS_REGION", "ap-south-1")
            sqs = boto3.client("sqs", region_name=region)
            resp = sqs.get_queue_attributes(
                QueueUrl=self.dlq_url,
                AttributeNames=["ApproximateNumberOfMessages"],
            )
            depth = int(resp["Attributes"].get("ApproximateNumberOfMessages", 0))

            # Update Prometheus metric
            try:
                from prometheus_client import Gauge
                dlq_depth = Gauge(
                    "pipeline_dlq_depth",
                    "Number of messages in the DLQ",
                    registry=None,
                )
                dlq_depth.set(depth)
            except Exception:
                pass

            if depth >= self.alert_threshold:
                logger.warning(
                    "DLQ depth=%d exceeds threshold=%d — manual intervention may be needed",
                    depth, self.alert_threshold,
                )

            return depth

        except Exception as exc:
            logger.error("Failed to check DLQ depth: %s", exc)
            return -1

    def peek_messages(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Peek at messages in the DLQ without consuming them.

        Args:
            limit: Maximum number of messages to peek (max 10).

        Returns:
            List of message summaries.
        """
        if not self.dlq_url:
            return []

        try:
            import boto3
            region = os.getenv("AWS_REGION", "ap-south-1")
            sqs = boto3.client("sqs", region_name=region)
            resp = sqs.receive_message(
                QueueUrl=self.dlq_url,
                MaxNumberOfMessages=min(limit, 10),
                VisibilityTimeout=0,  # Don't hide from other consumers
                AttributeNames=["All"],
            )

            messages = []
            for msg in resp.get("Messages", []):
                messages.append({
                    "message_id": msg.get("MessageId"),
                    "body_preview": msg.get("Body", "")[:200],
                    "receive_count": msg.get("Attributes", {}).get("ApproximateReceiveCount", "0"),
                    "first_received": msg.get("Attributes", {}).get("ApproximateFirstReceiveTimestamp"),
                    "sent_timestamp": msg.get("Attributes", {}).get("SentTimestamp"),
                })
            return messages

        except Exception as exc:
            logger.error("Failed to peek DLQ messages: %s", exc)
            return []

    def get_status(self) -> Dict[str, Any]:
        """Get full DLQ status report.

        Returns:
            Dict with depth, threshold, alert state, and sample messages.
        """
        depth = self.check_depth()
        return {
            "dlq_url": self.dlq_url or "not configured",
            "depth": depth,
            "alert_threshold": self.alert_threshold,
            "alert_active": depth >= self.alert_threshold,
            "sample_messages": self.peek_messages(limit=3) if depth > 0 else [],
        }
