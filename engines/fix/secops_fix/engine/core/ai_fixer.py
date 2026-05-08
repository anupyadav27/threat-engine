"""
AI Fixer — Mistral AI integration for context-aware code fix generation.

Strategy (adopted from peer's safepatch_engine.py and integrated into production engine):
  - Groups findings PER FILE so the AI sees the full file content + all issues at once.
  - One Mistral API call per file (not per finding) — cheaper and higher quality.
  - AI returns the full corrected file; the engine writes it back via git_patcher.

Environment variables:
  MISTRAL_API_KEY     — required (get from console.mistral.ai)
  MISTRAL_MODEL       — optional (default: mistral-medium)
"""

import logging
import os
from typing import Optional

from pydantic import BaseModel
from pydantic_ai import Agent, ModelRetry
from pydantic_ai.models.mistral import MistralModel

logger = logging.getLogger(__name__)


class _FixResult(BaseModel):
    """Structured output from the Mistral fix agent."""

    fixed_code: str  # full corrected file content, no markdown fences


def fix_file(
    file_content: str,
    findings: list,
    language: str,
) -> Optional[str]:
    """Send the full file content + all security findings to Mistral.

    Returns the corrected full file content, or None if the call fails
    or the API key is not configured.

    Each entry in `findings` should be a dict with:
        line             — int, 1-based line number
        message          — str, human-readable issue description
        rule_id          — str, scanner rule identifier
        recommendation   — str, how to fix (from rule metadata)
        compliant_example— str, safe code example (from rule metadata)

    Args:
        file_content: The full source file to be fixed.
        findings: List of finding dicts describing each security issue.
        language: Programming/config language of the file (e.g. "python").

    Returns:
        Corrected full file content string, or None on failure/skip.
    """
    api_key = os.getenv("MISTRAL_API_KEY", "").strip()
    if not api_key:
        logger.debug("MISTRAL_API_KEY not set — AI fix skipped, using regex fallback")
        return None

    model_name = os.getenv("MISTRAL_MODEL", "mistral-medium")

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
        f"[AI] Calling Mistral ({model_name}) for {len(findings)} finding(s) — "
        f"file size: {len(file_content)} chars"
    )

    # Agent is created inside fix_file so MISTRAL_API_KEY is guaranteed to be
    # present before MistralModel resolves it from the environment at construction.
    agent: Agent[None, _FixResult] = Agent(
        MistralModel(model_name),
        result_type=_FixResult,
        system_prompt=(
            "You are a precise security code-fixing assistant. "
            "Return only the corrected file content, nothing else. "
            "No markdown fences. No explanations."
        ),
    )

    @agent.result_validator
    async def _validate_fix(ctx, result: _FixResult) -> _FixResult:  # type: ignore[misc]
        if not result.fixed_code.strip():
            raise ModelRetry("Returned empty content — provide the full corrected file.")
        return result

    try:
        result = agent.run_sync(prompt)
        corrected = result.data.fixed_code.strip()
        logger.info("[AI] Fix received successfully")
        return corrected
    except Exception as e:
        logger.warning(f"[AI] Mistral call failed: {e}")
        return None
