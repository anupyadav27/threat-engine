"""
Pydantic models for threat-engine SQS pipeline events.

Every message placed on an SQS queue is a JSON-serialised ``PipelineEvent``.
The ``event_type`` field drives pipeline routing in the worker.

Typical flow::

    scan_requested  → pipeline_worker creates orchestration row,
                      runs stages sequentially
    stage_complete  → published after each stage succeeds (for monitoring)
    stage_failed    → published when a stage exhausts retries
    scan_complete   → published when all stages finish successfully
    scan_failed     → published when the pipeline is abandoned (DLQ or fatal)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field

# ── Type aliases ──────────────────────────────────────────────────────────────

EventType = Literal[
    "scan_requested",
    "stage_complete",
    "stage_failed",
    "scan_complete",
    "scan_failed",
]

Stage = Literal[
    "discovery",
    "inventory",
    "check",
    "threat",
    "compliance",
    "iam",
    "datasec",
    "secops",
]

# ── Models ────────────────────────────────────────────────────────────────────


class PipelineEvent(BaseModel):
    """A single pipeline event placed on an SQS queue.

    All fields except ``event_id`` and ``timestamp`` must be supplied by
    the publisher.

    Attributes:
        event_id: UUID used as the SQS ``MessageDeduplicationId`` (FIFO).
        event_type: Routing key for the pipeline worker.
        orchestration_id: UUID from ``scan_orchestration`` table.
        tenant_id: Tenant identifier (VARCHAR 255).
        account_id: Cloud account identifier.
        provider: Cloud provider slug (``"aws"`` / ``"azure"`` / …).
        stage: The pipeline stage this event relates to.
        scan_id: Engine-specific scan ID produced by this stage (if known).
        error: Human-readable error description for failed events.
        timestamp: ISO-8601 UTC timestamp of when the event was created.
        metadata: Arbitrary additional context (e.g. ``check_scan_id``).
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    orchestration_id: str
    tenant_id: str
    account_id: str
    provider: str = "aws"
    stage: Stage
    scan_id: Optional[str] = None
    error: Optional[str] = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_sqs_body(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict suitable for ``SQSClient.publish``.

        Pass ``event.event_id`` as the ``deduplication_id`` argument to
        ``SQSClient.publish`` to prevent duplicate delivery::

            client.publish(queue_url, event.to_sqs_body(),
                           deduplication_id=event.event_id)
        """
        return self.model_dump()

    @classmethod
    def from_sqs_message(cls, raw_message: Dict[str, Any]) -> "PipelineEvent":
        """Deserialise an SQS message dict into a ``PipelineEvent``.

        Args:
            raw_message: The dict returned by ``SQSClient.receive`` (must
                         contain a ``"Body"`` key with a JSON string).

        Returns:
            Parsed ``PipelineEvent``.

        Raises:
            pydantic.ValidationError: If required fields are missing.
            json.JSONDecodeError: If the body is not valid JSON.
        """
        data = json.loads(raw_message["Body"])
        return cls(**data)


# ── Factory helpers ───────────────────────────────────────────────────────────


def scan_requested(
    orchestration_id: str,
    tenant_id: str,
    account_id: str,
    provider: str = "aws",
    metadata: Optional[Dict[str, Any]] = None,
) -> PipelineEvent:
    """Create a ``scan_requested`` event (published by onboarding)."""
    return PipelineEvent(
        event_type="scan_requested",
        orchestration_id=orchestration_id,
        tenant_id=tenant_id,
        account_id=account_id,
        provider=provider,
        stage="discovery",
        metadata=metadata or {},
    )


def stage_complete(
    orchestration_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    stage: Stage,
    scan_id: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> PipelineEvent:
    """Create a ``stage_complete`` event (published by the pipeline worker)."""
    return PipelineEvent(
        event_type="stage_complete",
        orchestration_id=orchestration_id,
        tenant_id=tenant_id,
        account_id=account_id,
        provider=provider,
        stage=stage,
        scan_id=scan_id,
        metadata=metadata or {},
    )


def stage_failed(
    orchestration_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    stage: Stage,
    error: str,
) -> PipelineEvent:
    """Create a ``stage_failed`` event."""
    return PipelineEvent(
        event_type="stage_failed",
        orchestration_id=orchestration_id,
        tenant_id=tenant_id,
        account_id=account_id,
        provider=provider,
        stage=stage,
        error=error,
    )


def scan_complete(
    orchestration_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> PipelineEvent:
    """Create a ``scan_complete`` event (published when all stages finish)."""
    return PipelineEvent(
        event_type="scan_complete",
        orchestration_id=orchestration_id,
        tenant_id=tenant_id,
        account_id=account_id,
        provider=provider,
        stage="secops",  # last stage marker
    )
