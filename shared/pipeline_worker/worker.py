"""
Threat-Engine SQS Pipeline Worker
===================================

Polls the ``SQS_PIPELINE_QUEUE_URL`` queue for ``scan_requested`` events and
runs the full engine pipeline sequentially:

    inventory → check → threat → compliance + IAM + datasec (parallel)

Each stage is triggered via HTTP.  On success the message is deleted.  On
failure the message is left in the queue — after ``maxReceiveCount`` retries
(configured on the SQS queue) it is moved to the Dead-Letter Queue (DLQ).

Stage-level monitoring events are published to ``SQS_EVENTS_QUEUE_URL`` when
that variable is set (optional).

Environment variables
---------------------
SQS_PIPELINE_QUEUE_URL  (required) Input queue URL (FIFO recommended)
SQS_EVENTS_QUEUE_URL    (optional) Events queue URL for stage notifications
SQS_POLL_INTERVAL_S     (optional) Seconds between empty polls (default: 5)
SQS_VISIBILITY_TIMEOUT  (optional) Seconds visibility window (default: 3600)
AWS_REGION              (optional) AWS region (default: ap-south-1)
*_ENGINE_URL             (optional) Per-engine HTTP URL overrides

Run
---
    python -m shared.pipeline_worker.worker

    # or directly
    python shared/pipeline_worker/worker.py
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time
from typing import Optional

# Allow running directly or as a module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from shared.common.sqs import SQSClient
from shared.common.pipeline_events import (
    PipelineEvent,
    scan_complete,
    stage_complete,
    stage_failed,
)
from shared.pipeline_worker import handlers

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("pipeline_worker")

# ── Config ────────────────────────────────────────────────────────────────────

QUEUE_URL: str = os.environ["SQS_PIPELINE_QUEUE_URL"]
EVENTS_QUEUE_URL: Optional[str] = os.getenv("SQS_EVENTS_QUEUE_URL")
POLL_INTERVAL: int = int(os.getenv("SQS_POLL_INTERVAL_S", "5"))
VISIBILITY_TIMEOUT: int = int(os.getenv("SQS_VISIBILITY_TIMEOUT", "3600"))

# ── Pipeline runner ───────────────────────────────────────────────────────────


async def run_pipeline(event: PipelineEvent, sqs: SQSClient) -> None:
    """Execute the full pipeline for one ``scan_requested`` event.

    Runs stages in order:
      1. inventory
      2. check
      3. threat
      4. compliance + iam + datasec (parallel)

    Publishes ``stage_complete`` / ``stage_failed`` events to the events queue
    if ``SQS_EVENTS_QUEUE_URL`` is configured.

    Args:
        event: The ``scan_requested`` PipelineEvent.
        sqs: Shared SQS client instance.
    """
    oid = event.orchestration_id
    tid = event.tenant_id
    aid = event.account_id
    prov = event.provider

    logger.info("pipeline start orchestration_id=%s account=%s", oid, aid)

    check_scan_id: Optional[str] = None

    # ── Stage 1: Inventory ────────────────────────────────────────────────
    try:
        resp = await handlers.trigger_inventory(oid, tid, aid)
        inv_scan_id = (
            resp.get("scan_run_id") or resp.get("scan_id") or resp.get("inventory_scan_id")
        )
        logger.info("inventory complete scan_id=%s", inv_scan_id)
        _publish_event(sqs, stage_complete(oid, tid, aid, prov, "inventory", inv_scan_id or ""))
    except Exception as exc:
        logger.error("inventory failed oid=%s error=%s", oid, exc)
        _publish_event(sqs, stage_failed(oid, tid, aid, prov, "inventory", str(exc)))
        # Non-fatal — check can still use discovery_scan_id directly

    # ── Stage 2: Check ────────────────────────────────────────────────────
    try:
        resp = await handlers.trigger_check(oid, prov)
        check_scan_id = resp.get("check_scan_id") or resp.get("scan_id")
        logger.info("check complete scan_id=%s", check_scan_id)
        _publish_event(sqs, stage_complete(oid, tid, aid, prov, "check", check_scan_id or ""))
    except Exception as exc:
        logger.error("check failed oid=%s error=%s", oid, exc)
        _publish_event(sqs, stage_failed(oid, tid, aid, prov, "check", str(exc)))
        # Use orchestration_id as fallback for downstream

    # ── Stage 3: Threat ───────────────────────────────────────────────────
    try:
        resp = await handlers.trigger_threat(oid, prov, check_scan_id)
        threat_scan_id = resp.get("scan_run_id") or resp.get("scan_id") or oid
        logger.info("threat complete scan_id=%s", threat_scan_id)
        _publish_event(sqs, stage_complete(oid, tid, aid, prov, "threat", threat_scan_id))
    except Exception as exc:
        logger.error("threat failed oid=%s error=%s", oid, exc)
        _publish_event(sqs, stage_failed(oid, tid, aid, prov, "threat", str(exc)))
        # Continue — analytics engines still useful without threat data

    # ── Stage 4: Compliance + IAM + DataSec (parallel) ───────────────────
    results = await asyncio.gather(
        handlers.trigger_compliance(oid),
        handlers.trigger_iam(oid),
        handlers.trigger_datasec(oid),
        return_exceptions=True,
    )

    parallel_stages = ["compliance", "iam", "datasec"]
    for stage_name, result in zip(parallel_stages, results):
        if isinstance(result, Exception):
            logger.error("%s failed oid=%s error=%s", stage_name, oid, result)
            _publish_event(sqs, stage_failed(oid, tid, aid, prov, stage_name, str(result)))  # type: ignore[arg-type]
        else:
            sid = result.get("scan_id") or result.get(f"{stage_name}_scan_id") or ""
            logger.info("%s complete scan_id=%s", stage_name, sid)
            _publish_event(sqs, stage_complete(oid, tid, aid, prov, stage_name, sid))  # type: ignore[arg-type]

    # ── Final: publish scan_complete ──────────────────────────────────────
    _publish_event(sqs, scan_complete(oid, tid, aid, prov))
    logger.info("pipeline complete orchestration_id=%s", oid)


def _publish_event(sqs: SQSClient, event: PipelineEvent) -> None:
    """Publish *event* to the events queue if configured (best-effort)."""
    if not EVENTS_QUEUE_URL:
        return
    try:
        sqs.publish(
            EVENTS_QUEUE_URL,
            event.to_sqs_body(),
            deduplication_id=event.event_id,
            group_id=event.orchestration_id,
        )
    except Exception as exc:
        logger.warning("failed to publish event type=%s error=%s", event.event_type, exc)


# ── Main poll loop ────────────────────────────────────────────────────────────


def run() -> None:
    """Blocking main loop: poll queue, process messages, repeat."""
    sqs = SQSClient()
    logger.info(
        "pipeline_worker starting queue=%s visibility=%ds",
        QUEUE_URL.rsplit("/", 1)[-1],
        VISIBILITY_TIMEOUT,
    )

    # Graceful shutdown on SIGTERM / SIGINT
    _running = [True]

    def _stop(signum, frame):  # noqa: ANN001
        logger.info("signal %d received — shutting down after current message", signum)
        _running[0] = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while _running[0]:
        messages = sqs.receive(
            QUEUE_URL,
            max_messages=1,
            wait_seconds=20,
            visibility_timeout=VISIBILITY_TIMEOUT,
        )

        if not messages:
            time.sleep(POLL_INTERVAL)
            continue

        msg = messages[0]
        receipt = msg["ReceiptHandle"]

        try:
            event = PipelineEvent.from_sqs_message(msg)
        except Exception as exc:
            logger.error("malformed message — deleting to avoid infinite loop: %s", exc)
            sqs.delete(QUEUE_URL, receipt)
            continue

        if event.event_type != "scan_requested":
            logger.warning(
                "unexpected event_type=%s in pipeline queue — deleting", event.event_type
            )
            sqs.delete(QUEUE_URL, receipt)
            continue

        logger.info(
            "processing event_id=%s orchestration_id=%s",
            event.event_id,
            event.orchestration_id,
        )

        try:
            asyncio.run(run_pipeline(event, sqs))
            sqs.delete(QUEUE_URL, receipt)
            logger.info("message acked event_id=%s", event.event_id)
        except Exception as exc:
            # Leave message in queue — SQS will re-deliver after visibility timeout.
            # After maxReceiveCount failures, SQS moves it to the DLQ automatically.
            logger.error(
                "pipeline failed event_id=%s error=%s — message left for retry",
                event.event_id,
                exc,
            )

    logger.info("pipeline_worker stopped")


if __name__ == "__main__":
    run()
