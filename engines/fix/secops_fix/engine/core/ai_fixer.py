"""
AI Fixer — Mistral AI integration for context-aware code fix generation.

Strategy (adopted from peer's safepatch_engine.py and integrated into production engine):
  - Groups findings PER FILE so the AI sees the full file content + all issues at once.
  - One Mistral API call per file (not per finding) — cheaper and higher quality.
  - AI returns the full corrected file; the engine writes it back via git_patcher.

Environment variables:
  MISTRAL_API_KEY     — required (get from console.mistral.ai)
  MISTRAL_MODEL       — optional (default: mistral-medium)
  MISTRAL_TIMEOUT     — optional seconds (default: 120)
"""

import logging
import os
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"

# Transient status codes safe to retry with exponential backoff
_RETRYABLE_STATUS    = {429, 500, 502, 503, 504}
_MISTRAL_MAX_RETRIES = 3
_MISTRAL_BACKOFF_BASE = 2   # seconds — doubles each attempt (2 → 4 → 8)


def fix_file(
    file_content: str,
    findings: list,
    language: str,
) -> Optional[str]:
    """
    Send the full file content + all security findings to Mistral.
    Returns the corrected full file content, or None if the call fails
    or the API key is not configured.

    Each entry in `findings` should be a dict with:
        line             — int, 1-based line number
        message          — str, human-readable issue description
        rule_id          — str, scanner rule identifier
        recommendation   — str, how to fix (from rule metadata)
        compliant_example— str, safe code example (from rule metadata)

    Adapted from peer's _call_mistral() in safepatch_engine.py.
    """
    api_key = os.getenv("MISTRAL_API_KEY", "").strip()
    if not api_key:
        logger.debug("MISTRAL_API_KEY not set — AI fix skipped, using regex fallback")
        return None

    model   = os.getenv("MISTRAL_MODEL",   "mistral-medium")
    timeout = int(os.getenv("MISTRAL_TIMEOUT", "120"))

    # Build human-readable issues block
    issues_text = "\n".join(
        "- Line {line}: {message}  [Rule: {rule_id}]\n"
        "  Fix: {recommendation}\n"
        "  Example: {compliant_example}".format(**f)
        for f in findings
    )

    prompt = (
        f"You are a security-focused {language} code-fixing assistant.\n\n"
        f"Here is the complete file content:\n"
        f"```{language}\n{file_content}\n```\n\n"
        f"Security issues that must be fixed (ALL of them):\n{issues_text}\n\n"
        "Instructions:\n"
        "- Fix ONLY the listed security issues. Do NOT change anything else.\n"
        "- Preserve the original indentation, variable names, and code style exactly.\n"
        "- Do NOT add imports unless they are strictly required by the fix.\n"
        "- Return ONLY the full corrected file content.\n"
        "- No explanations. No markdown code fences. No comments about changes made."
    )

    logger.info(
        f"[AI] Calling Mistral ({model}) for {len(findings)} finding(s) — "
        f"file size: {len(file_content)} chars"
    )

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a precise security code-fixing assistant. "
                    "You return only the corrected file content, nothing else."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 8192,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    for attempt in range(1, _MISTRAL_MAX_RETRIES + 1):
        try:
            resp = requests.post(
                MISTRAL_API_URL,
                headers=headers,
                json=payload,
                timeout=timeout,
            )

            # Transient server-side errors — back off and retry
            if resp.status_code in _RETRYABLE_STATUS and attempt < _MISTRAL_MAX_RETRIES:
                wait = _MISTRAL_BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning(
                    f"[AI] Mistral {resp.status_code} (attempt {attempt}/{_MISTRAL_MAX_RETRIES})"
                    f" — retrying in {wait}s"
                )
                time.sleep(wait)
                continue

            resp.raise_for_status()
            corrected = resp.json()["choices"][0]["message"]["content"].strip()

            # Strip markdown fences if model accidentally added them
            if corrected.startswith("```"):
                lines = corrected.splitlines()
                corrected = "\n".join(
                    line for line in lines[1:]
                    if not line.strip().startswith("```")
                ).strip()

            if not corrected:
                logger.warning("[AI] Mistral returned empty content")
                return None

            logger.info(
                "[AI] Fix received successfully"
                + (f" (attempt {attempt})" if attempt > 1 else "")
            )
            return corrected

        except requests.exceptions.Timeout:
            if attempt == _MISTRAL_MAX_RETRIES:
                logger.warning(f"[AI] Mistral timed out after {timeout}s (all retries exhausted)")
                return None
            wait = _MISTRAL_BACKOFF_BASE * (2 ** (attempt - 1))
            logger.warning(
                f"[AI] Mistral timeout (attempt {attempt}/{_MISTRAL_MAX_RETRIES})"
                f" — retrying in {wait}s"
            )
            time.sleep(wait)

        except requests.exceptions.HTTPError as e:
            http_status = e.response.status_code if e.response is not None else "?"
            if http_status not in _RETRYABLE_STATUS or attempt == _MISTRAL_MAX_RETRIES:
                logger.warning(
                    f"[AI] Mistral HTTP {http_status} — {e.response.text[:200] if e.response else ''}"
                )
                return None
            wait = _MISTRAL_BACKOFF_BASE * (2 ** (attempt - 1))
            logger.warning(
                f"[AI] Mistral HTTP {http_status} (attempt {attempt}/{_MISTRAL_MAX_RETRIES})"
                f" — retrying in {wait}s"
            )
            time.sleep(wait)

        except Exception as e:
            logger.warning(f"[AI] Mistral call failed: {e}")
            return None

    return None
