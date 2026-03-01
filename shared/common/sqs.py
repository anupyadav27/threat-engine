"""
AWS SQS client helpers for the threat-engine pipeline.

Thin boto3 wrapper providing publish / receive / delete / visibility-extend
operations.  All pipeline messages are JSON-serialised ``PipelineEvent``
objects (see ``pipeline_events.py``).

FIFO queues are assumed throughout (queue URLs ending in ``.fifo``).
Standard queues work too — MessageGroupId / MessageDeduplicationId kwargs
are only added for FIFO queues.

Usage::

    from shared.common.sqs import SQSClient

    client = SQSClient()
    client.publish(os.environ["SQS_PIPELINE_QUEUE_URL"], event.to_sqs_body(),
                   deduplication_id=event.event_id)

    for msg in client.receive(queue_url, max_messages=1):
        try:
            process(msg["Body"])
            client.delete(queue_url, msg["ReceiptHandle"])
        except Exception:
            pass  # message returns to queue after visibility timeout
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def _dedup_id(body: str) -> str:
    """SHA-256 hash of message body, truncated to 64 chars (SQS limit: 128)."""
    return hashlib.sha256(body.encode()).hexdigest()[:64]


class SQSClient:
    """Thread-safe, reusable boto3 SQS wrapper.

    Args:
        region: AWS region.  Defaults to ``AWS_REGION`` env var, then
                ``ap-south-1``.
    """

    def __init__(self, region: Optional[str] = None) -> None:
        region = region or os.getenv("AWS_REGION", "ap-south-1")
        self._sqs = boto3.client("sqs", region_name=region)

    # ── Publish ──────────────────────────────────────────────────────────────

    def publish(
        self,
        queue_url: str,
        message: Dict[str, Any],
        *,
        deduplication_id: Optional[str] = None,
        group_id: str = "pipeline",
    ) -> str:
        """Publish *message* to *queue_url*.  Returns the SQS ``MessageId``.

        For FIFO queues the ``MessageGroupId`` is set to *group_id* and
        ``MessageDeduplicationId`` is set to *deduplication_id* (or a hash
        of the body when not supplied).

        Args:
            queue_url: Full SQS queue URL.
            message: JSON-serialisable dict.
            deduplication_id: Idempotency key (FIFO only).  Use the event's
                              ``event_id`` to prevent duplicate delivery.
            group_id: FIFO message group.  All pipeline messages use the
                      default ``"pipeline"`` group so ordering is preserved.

        Returns:
            SQS ``MessageId`` string.

        Raises:
            botocore.exceptions.ClientError: On SQS API failure.
        """
        body = json.dumps(message, default=str)
        kwargs: Dict[str, Any] = {
            "QueueUrl": queue_url,
            "MessageBody": body,
        }
        if queue_url.endswith(".fifo"):
            kwargs["MessageGroupId"] = group_id
            kwargs["MessageDeduplicationId"] = deduplication_id or _dedup_id(body)

        try:
            resp = self._sqs.send_message(**kwargs)
            msg_id: str = resp["MessageId"]
            logger.info("sqs.publish msg_id=%s queue=%s", msg_id, _short(queue_url))
            return msg_id
        except ClientError as exc:
            logger.error("sqs.publish failed queue=%s error=%s", _short(queue_url), exc)
            raise

    # ── Receive ──────────────────────────────────────────────────────────────

    def receive(
        self,
        queue_url: str,
        *,
        max_messages: int = 1,
        wait_seconds: int = 20,
        visibility_timeout: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Long-poll *queue_url* and return raw SQS message dicts.

        Each message dict contains at minimum:
        ``MessageId``, ``ReceiptHandle``, ``Body``, ``Attributes``.

        Args:
            queue_url: Full SQS queue URL.
            max_messages: 1–10.  Default 1.
            wait_seconds: Long-poll duration (0–20 s).  Default 20.
            visibility_timeout: Override the queue's default visibility
                                timeout for these messages (seconds).

        Returns:
            List of raw SQS message dicts (may be empty).
        """
        kwargs: Dict[str, Any] = {
            "QueueUrl": queue_url,
            "MaxNumberOfMessages": max_messages,
            "WaitTimeSeconds": wait_seconds,
            "AttributeNames": ["All"],
            "MessageAttributeNames": ["All"],
        }
        if visibility_timeout is not None:
            kwargs["VisibilityTimeout"] = visibility_timeout

        try:
            resp = self._sqs.receive_message(**kwargs)
            messages = resp.get("Messages", [])
            if messages:
                logger.debug("sqs.receive got %d msg(s) from %s", len(messages), _short(queue_url))
            return messages
        except ClientError as exc:
            logger.error("sqs.receive failed queue=%s error=%s", _short(queue_url), exc)
            raise

    # ── Delete (ack) ─────────────────────────────────────────────────────────

    def delete(self, queue_url: str, receipt_handle: str) -> None:
        """Acknowledge successful processing — removes message from queue.

        Args:
            queue_url: Full SQS queue URL.
            receipt_handle: Value from the received message's
                            ``ReceiptHandle`` field.
        """
        try:
            self._sqs.delete_message(
                QueueUrl=queue_url, ReceiptHandle=receipt_handle
            )
            logger.debug("sqs.delete receipt=%s...", receipt_handle[:20])
        except ClientError as exc:
            logger.error("sqs.delete failed error=%s", exc)
            raise

    # ── Visibility ───────────────────────────────────────────────────────────

    def extend_visibility(
        self, queue_url: str, receipt_handle: str, timeout_seconds: int
    ) -> None:
        """Extend the visibility timeout so the message stays invisible.

        Call periodically during long-running pipeline stages to prevent
        the message from returning to the queue before processing finishes.

        Args:
            queue_url: Full SQS queue URL.
            receipt_handle: From the received message.
            timeout_seconds: New visibility timeout from *now* (0–43200 s).
        """
        try:
            self._sqs.change_message_visibility(
                QueueUrl=queue_url,
                ReceiptHandle=receipt_handle,
                VisibilityTimeout=timeout_seconds,
            )
            logger.debug("sqs.extend_visibility +%ds", timeout_seconds)
        except ClientError as exc:
            # Non-fatal — log and continue.  The message may re-appear in
            # queue if visibility expires, but DLQ will catch it after N retries.
            logger.warning("sqs.extend_visibility failed error=%s", exc)


def _short(queue_url: str) -> str:
    """Return just the queue name from a full URL for log brevity."""
    return queue_url.rsplit("/", 1)[-1]
