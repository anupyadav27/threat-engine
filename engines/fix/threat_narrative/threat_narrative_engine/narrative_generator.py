"""
Core orchestration for the Attack Path Narrative Engine.

For each attack path, this module:
  1. Reads context from attack_paths + enrichment tables via db_reader
  2. Builds prompts via prompt_templates
  3. Calls the LLM API (Anthropic Claude or Mistral fallback)
  4. Validates and truncates outputs
  5. Writes results to attack_paths.attack_story via db_writer

LLM failure modes are handled gracefully — never raises to the caller.
"""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("threat_narrative")

# ── LLM model constants ────────────────────────────────────────────────────────
ANTHROPIC_MODEL = "claude-sonnet-4-6"
MISTRAL_MODEL = "mistral-large-latest"
LLM_TIMEOUT_SECONDS = 30.0
BETWEEN_DETECTION_SLEEP = 0.5  # throttle between detections (simple rate-limit avoidance)
RATE_LIMIT_RETRY_SLEEP = 60.0  # wait after 429 before one retry


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class NarrativeResult:
    """Result of one narrative generation attempt.

    Attributes:
        detection_id: The detection this result is for.
        skipped: True if context was insufficient or LLM not configured.
        failed: True if LLM call failed (timeout, rate limit, invalid output).
        chain_of_consequence: Generated text (None if skipped/failed).
        stakes_narrative: Generated text (None if skipped/failed).
        model: LLM model identifier used (None if skipped/failed).
    """

    detection_id: str
    skipped: bool = False
    failed: bool = False
    chain_of_consequence: str | None = None
    stakes_narrative: str | None = None
    model: str | None = None


# ── LLM provider detection ─────────────────────────────────────────────────────

def get_llm_provider() -> str | None:
    """Return the available LLM provider identifier.

    Returns:
        "anthropic" if ANTHROPIC_API_KEY is set,
        "mistral" if only MISTRAL_API_KEY is set,
        None if neither key is configured.
    """
    if os.getenv("ANTHROPIC_API_KEY", "").strip():
        return "anthropic"
    if os.getenv("MISTRAL_API_KEY", "").strip():
        return "mistral"
    return None


# ── LLM call implementations ───────────────────────────────────────────────────

async def _call_anthropic(system: str, user: str, max_tokens: int = 200) -> str:
    """Call Anthropic Claude synchronously in an executor.

    The anthropic SDK is sync; we run it in the default executor to avoid
    blocking the event loop.

    Args:
        system: System prompt.
        user: User message content.
        max_tokens: Maximum tokens in the response.

    Returns:
        Stripped response text.

    Raises:
        Exception: On any API failure (let caller handle).
    """
    import anthropic

    def _sync_call() -> str:
        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
        message = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": user}],
            system=system,
        )
        return message.content[0].text.strip()

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_call)


async def _call_mistral(system: str, user: str, max_tokens: int = 200) -> str:
    """Call Mistral API via direct HTTP using requests (no heavy SDK).

    Args:
        system: System prompt.
        user: User message content.
        max_tokens: Maximum tokens in the response.

    Returns:
        Stripped response text.

    Raises:
        Exception: On any API failure (let caller handle).
    """
    import requests

    def _sync_call() -> str:
        api_key = os.getenv("MISTRAL_API_KEY", "")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": MISTRAL_MODEL,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        resp = requests.post(
            "https://api.mistral.ai/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=LLM_TIMEOUT_SECONDS,
        )
        if resp.status_code == 429:
            raise _RateLimitError("Mistral rate limit")
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_call)


class _RateLimitError(Exception):
    """Raised when the LLM API returns HTTP 429."""


async def _call_llm(
    system: str,
    user: str,
    provider: str,
    max_tokens: int = 200,
    detection_id: str = "",
) -> str:
    """Call the LLM with timeout and one retry on 429.

    Args:
        system: System prompt.
        user: User message content.
        provider: "anthropic" or "mistral".
        max_tokens: Maximum response tokens.
        detection_id: Detection ID for log context.

    Returns:
        Stripped response text.

    Raises:
        asyncio.TimeoutError: If LLM takes longer than LLM_TIMEOUT_SECONDS.
        Exception: On unrecoverable LLM failure after retry.
    """
    async def _attempt() -> str:
        if provider == "anthropic":
            return await _call_anthropic(system, user, max_tokens)
        return await _call_mistral(system, user, max_tokens)

    try:
        return await asyncio.wait_for(_attempt(), timeout=LLM_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(
            "LLM call timed out",
            extra={"detection_id": detection_id, "provider": provider, "timeout": LLM_TIMEOUT_SECONDS},
        )
        raise
    except _RateLimitError:
        logger.warning(
            "LLM rate limit (429) — sleeping %ss then retrying once",
            RATE_LIMIT_RETRY_SLEEP,
            extra={"detection_id": detection_id, "provider": provider},
        )
        await asyncio.sleep(RATE_LIMIT_RETRY_SLEEP)
        try:
            return await asyncio.wait_for(_attempt(), timeout=LLM_TIMEOUT_SECONDS)
        except _RateLimitError:
            logger.warning(
                "LLM rate limit (429) on retry — marking as failed",
                extra={"detection_id": detection_id, "provider": provider},
            )
            raise


# ── Output validation ─────────────────────────────────────────────────────────

def _validate_chain(text: str) -> str | None:
    """Validate and truncate chain_of_consequence.

    Args:
        text: Raw LLM output.

    Returns:
        Validated (possibly truncated) string, or None if invalid.
    """
    text = text.strip()[:500]  # hard cap at 500 chars
    if not text:
        return None
    # Accept any output — if it doesn't start with "If" just truncate, don't fail
    return text


def _validate_stakes(text: str) -> str | None:
    """Validate and truncate stakes_narrative.

    Args:
        text: Raw LLM output.

    Returns:
        Validated (possibly truncated) string, or None if too short.
    """
    text = text.strip()[:4000]  # hard cap at 4000 chars
    if len(text) < 50:
        return None  # treat as failed — leave NULL
    return text


# ── Main generation entry point ───────────────────────────────────────────────

async def generate_for_detection(
    detection_id: str,
    scan_run_id: str,
) -> NarrativeResult:
    """Generate chain_of_consequence and stakes_narrative for one detection.

    Steps:
      1. Read context from all source tables via db_reader
      2. If context is insufficient: return NarrativeResult(skipped=True)
      3. Build chain_of_consequence prompt and call LLM
      4. Build stakes_narrative prompt (using chain as first sentence) and call LLM
      5. Validate outputs
      6. Write to DB via db_writer

    Any LLM exception: log WARNING, return NarrativeResult(failed=True).
    DB connectivity failure: re-raised (pipeline step should surface this).

    Args:
        detection_id: UUID of the threat detection.
        scan_run_id: The pipeline scan run UUID.

    Returns:
        NarrativeResult with outcome details.
    """
    from threat_narrative_engine import db_reader, db_writer
    from threat_narrative_engine.prompt_templates import (
        build_chain_user_prompt,
        build_stakes_user_prompt,
        CHAIN_SYSTEM,
        STAKES_SYSTEM,
    )

    provider = get_llm_provider()

    # ── Read context ──────────────────────────────────────────────────────────
    # DB errors from db_reader propagate (infrastructure failures)
    ctx = db_reader.read_path_context(scan_run_id, detection_id)

    # ── Sufficiency check ─────────────────────────────────────────────────────
    if not ctx.get("entry_point_uid") or not ctx.get("chain_type"):
        logger.info(
            "Skipping generation — insufficient context",
            extra={
                "path_id": detection_id,
                "has_entry_point_uid": bool(ctx.get("entry_point_uid")),
                "has_chain_type": bool(ctx.get("chain_type")),
            },
        )
        return NarrativeResult(detection_id=detection_id, skipped=True)

    # ── LLM availability check ────────────────────────────────────────────────
    if provider is None:
        logger.info(
            "LLM key not configured — skipping narrative generation",
            extra={"detection_id": detection_id},
        )
        return NarrativeResult(detection_id=detection_id, skipped=True)

    model_id = ANTHROPIC_MODEL if provider == "anthropic" else MISTRAL_MODEL

    # ── Generate chain_of_consequence ─────────────────────────────────────────
    try:
        chain_prompt = build_chain_user_prompt(ctx)
        chain_raw = await _call_llm(
            system=CHAIN_SYSTEM,
            user=chain_prompt,
            provider=provider,
            max_tokens=200,
            detection_id=detection_id,
        )
        chain_text = _validate_chain(chain_raw)
        if chain_text is None:
            logger.warning(
                "chain_of_consequence validation failed — marking as failed",
                extra={"detection_id": detection_id},
            )
            return NarrativeResult(detection_id=detection_id, failed=True)
    except Exception as exc:
        logger.warning(
            "LLM call for chain_of_consequence failed",
            extra={"detection_id": detection_id, "error": str(exc)},
        )
        return NarrativeResult(detection_id=detection_id, failed=True)

    # ── Generate stakes_narrative ─────────────────────────────────────────────
    try:
        stakes_prompt = build_stakes_user_prompt(ctx, chain_text)
        stakes_raw = await _call_llm(
            system=STAKES_SYSTEM,
            user=stakes_prompt,
            provider=provider,
            max_tokens=600,
            detection_id=detection_id,
        )
        stakes_text = _validate_stakes(stakes_raw)
        if stakes_text is None:
            logger.warning(
                "stakes_narrative too short — leaving NULL",
                extra={"detection_id": detection_id, "length": len(stakes_raw)},
            )
            # chain was valid — write partial (chain only), stakes NULL
            # Per spec: NULL is valid fallback for individual fields
            stakes_text = None
    except Exception as exc:
        logger.warning(
            "LLM call for stakes_narrative failed",
            extra={"detection_id": detection_id, "error": str(exc)},
        )
        stakes_text = None

    # ── Write to DB ───────────────────────────────────────────────────────────
    # DB write failure propagates — infrastructure issue, not LLM issue
    db_writer.write_narrative(
        detection_id=detection_id,
        chain=chain_text,
        stakes=stakes_text or "",
        model=model_id,
    )

    return NarrativeResult(
        detection_id=detection_id,
        chain_of_consequence=chain_text,
        stakes_narrative=stakes_text,
        model=model_id,
    )


async def generate_for_scan(scan_run_id: str) -> dict[str, int]:
    """Generate narratives for all detections in a scan run.

    Processes detections sequentially with a small sleep between each to
    avoid LLM rate limits. Does NOT raise on LLM failures.

    Args:
        scan_run_id: The pipeline scan run UUID.

    Returns:
        Dict with keys: processed, skipped, failed, total.

    Raises:
        psycopg2.OperationalError: If the threat DB is unreachable.
    """
    from threat_narrative_engine import db_reader

    provider = get_llm_provider()
    if provider is None:
        logger.info(
            "LLM key not configured — skipping all narrative generation for scan",
            extra={"scan_run_id": scan_run_id},
        )

    detection_ids = db_reader.list_path_ids(scan_run_id)
    total = len(detection_ids)
    processed = skipped = failed = 0

    logger.info(
        "Starting attack path narrative generation",
        extra={
            "scan_run_id": scan_run_id,
            "total_paths": total,
            "provider": provider or "none",
        },
    )

    for detection_id in detection_ids:
        result = await generate_for_detection(detection_id, scan_run_id)

        if result.skipped:
            skipped += 1
        elif result.failed:
            failed += 1
        else:
            processed += 1

        # Throttle between detections to avoid rate limits
        if total > 1:
            await asyncio.sleep(BETWEEN_DETECTION_SLEEP)

    logger.info(
        "Attack path narrative generation complete",
        extra={
            "scan_run_id": scan_run_id,
            "processed": processed,
            "skipped": skipped,
            "failed": failed,
            "total": total,
        },
    )

    return {
        "processed": processed,
        "skipped": skipped,
        "failed": failed,
        "total": total,
    }
