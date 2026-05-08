"""
Contract Check Agent — deterministic field matching + DeepSeek suggestion generation.

Architecture (new):
  1. Run all 4 parsers in Python (same as before)
  2. diff_layers() — deterministic Python logic finds confirmed gaps
     - snake_case ↔ camelCase normalization
     - Array / nested path passthrough inference
     - JSONB coverage, computed-field skip, extra="allow" downgrade
  3. DeepSeek is called ONCE — only to write concrete suggestion text
     for confirmed gaps and produce a 2-sentence human summary.
     It no longer decides what is or isn't a gap.

This eliminates the false-positive flood that plagued the LLM-only approach.

Environment:
  DEEPSEEK_API_KEY    — optional override  (default: baked-in key)
  DEEPSEEK_MODEL      — optional           (default: deepseek-chat)
"""

from __future__ import annotations
import json
import logging
import os
import sys

import openai

sys.path.insert(0, os.path.dirname(__file__))

from models import ContractReport, LayerContract, FieldMismatch
from matcher import diff_layers, FieldGap

logger = logging.getLogger(__name__)


# ── Client factory ────────────────────────────────────────────────────────────

_DEEPSEEK_KEY = "sk-3d7acb8511ad4da18e8b0c89733f472b"


def _make_client() -> tuple[openai.OpenAI, str]:
    key   = os.getenv("DEEPSEEK_API_KEY", _DEEPSEEK_KEY).strip()
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    return openai.OpenAI(api_key=key, base_url="https://api.deepseek.com"), model


# ── Suggestion generation (LLM) ───────────────────────────────────────────────

_SUGGESTION_PROMPT = """\
You are a senior full-stack engineer reviewing contract gaps in a CSPM platform.

The platform has 4 layers:
  UI (Next.js JSX)  →  BFF (Python FastAPI gateway shared/api_gateway/bff/)
  →  Engine (FastAPI microservice engines/<engine>/)  →  DB (PostgreSQL)

For each gap below, write a SHORT, CONCRETE suggestion (max 120 chars) naming the
exact file path and specific change needed.  Return ONLY valid JSON — an array of
objects with keys "field_path" and "suggestion".  No markdown, no extra text.

view_name: {view_name}
engine_name: {engine_name}
bff_file: {bff_file}
engine_files: {engine_files}

gaps:
{gaps_json}
"""

_SUMMARY_PROMPT = """\
You are a senior full-stack engineer. Write a 2-sentence developer-facing summary
for these contract check results.  Be specific about what to fix first.
No markdown.

view_name: {view_name}
breaking: {breaking}
warning: {warning}
coverage_score: {score}
gaps (sample): {sample}
"""


def _llm_suggestions(
    gaps: list[FieldGap],
    view_name: str,
    engine_name: str,
    bff_data: dict,
    engine_data: dict,
) -> dict[str, str]:
    """
    Call DeepSeek once to fill suggestion text for each gap.
    Returns dict mapping field_path → suggestion string.
    """
    if not gaps:
        return {}

    client, model = _make_client()
    bff_file      = bff_data.get("source_files", ["shared/api_gateway/bff/"])[-1]
    engine_files  = engine_data.get("source_files", [f"engines/{engine_name}/"])

    gaps_simple = [
        {
            "field_path": g.field_path,
            "layer_from": g.layer_from,
            "layer_to":   g.layer_to,
            "issue":      g.issue,
            "severity":   g.severity,
        }
        for g in gaps
    ]

    prompt = _SUGGESTION_PROMPT.format(
        view_name=view_name,
        engine_name=engine_name,
        bff_file=bff_file,
        engine_files=engine_files,
        gaps_json=json.dumps(gaps_simple, indent=2),
    )

    logger.info(f"[ContractAgent] Requesting suggestions for {len(gaps)} gaps …")
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=4096,
        temperature=0,
    )
    raw = resp.choices[0].message.content or "[]"
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
        raw = raw.rsplit("```", 1)[0]

    try:
        items = json.loads(raw)
        if isinstance(items, list):
            return {item["field_path"]: item.get("suggestion", "") for item in items}
    except Exception as exc:
        logger.warning(f"[ContractAgent] suggestion parse failed: {exc}")

    return {}


def _llm_summary(
    view_name: str,
    breaking: int,
    warning: int,
    score: float,
    gaps: list[FieldGap],
) -> str:
    """Generate a 2-sentence summary for the report."""
    if not gaps:
        return f"{view_name} contract is clean — all UI fields are backed by BFF, engine, and DB."

    client, model = _make_client()
    sample = [{"field": g.field_path, "layer": f"{g.layer_from}→{g.layer_to}"} for g in gaps[:5]]
    prompt = _SUMMARY_PROMPT.format(
        view_name=view_name,
        breaking=breaking,
        warning=warning,
        score=round(score),
        sample=json.dumps(sample),
    )

    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=256,
        temperature=0,
    )
    return (resp.choices[0].message.content or "").strip()


# ── Public API ─────────────────────────────────────────────────────────────────

def run_contract_check(
    view_name: str,
    engine_name: str,
    *,
    extra_engines: list[str] | None = None,
) -> ContractReport:
    """
    Run the full end-to-end contract check for one BFF view.

    Steps:
      1. Run all 4 parsers
      2. diff_layers() — deterministic gap detection (no LLM)
      3. _llm_suggestions() — DeepSeek fills concrete suggestion text
      4. _llm_summary() — DeepSeek writes 2-sentence summary
      5. Build ContractReport
    """
    from parsers.ui_parser    import extract_ui_fields
    from parsers.bff_parser   import extract_bff_fields
    from parsers.engine_parser import extract_engine_fields
    from parsers.db_parser    import extract_db_columns

    extra = extra_engines or []

    logger.info(f"[ContractAgent] Collecting parser data for view={view_name}")

    ui_data     = extract_ui_fields(view_name)
    bff_data    = extract_bff_fields(view_name)
    engine_data = extract_engine_fields(engine_name)
    db_data     = extract_db_columns(engine_name)

    # Merge extra engine fields (e.g. risk data shown on threat page)
    for eng in extra:
        extra_eng = extract_engine_fields(eng)
        extra_db  = extract_db_columns(eng)
        engine_data["fields"] = list(set(engine_data["fields"] + extra_eng["fields"]))
        db_data["columns"]    = list(set(db_data["columns"]    + extra_db["columns"]))
        db_data["jsonb_columns"] = list(set(
            db_data.get("jsonb_columns", []) + extra_db.get("jsonb_columns", [])
        ))

    # ── Step 2: deterministic diff ────────────────────────────────────────────
    gaps = diff_layers(ui_data, bff_data, engine_data, db_data)

    breaking = sum(1 for g in gaps if g.severity == "breaking")
    warning  = sum(1 for g in gaps if g.severity == "warning")
    score    = max(0.0, 100.0 - 15 * breaking - 5 * warning)

    logger.info(
        f"[ContractAgent] Deterministic diff: {len(gaps)} gaps "
        f"breaking={breaking} warning={warning} score={score:.0f}"
    )

    # ── Step 3: LLM suggestions ───────────────────────────────────────────────
    suggestions = _llm_suggestions(gaps, view_name, engine_name, bff_data, engine_data)
    for g in gaps:
        g.suggestion = suggestions.get(g.field_path, f"Add '{g.field_path}' to {g.layer_to} layer")

    # ── Step 4: LLM summary ───────────────────────────────────────────────────
    summary = _llm_summary(view_name, breaking, warning, score, gaps)

    # ── Step 5: build report ──────────────────────────────────────────────────
    mismatches = [
        FieldMismatch(
            layer_from=g.layer_from,
            layer_to=g.layer_to,
            field_path=g.field_path,
            issue=g.issue,          # type: ignore[arg-type]
            severity=g.severity,    # type: ignore[arg-type]
            suggestion=g.suggestion,
        )
        for g in gaps
    ]

    layers = _build_layers(ui_data, bff_data, engine_data, db_data)

    report = ContractReport(
        view_name=view_name,
        layers=layers,
        mismatches=mismatches,
        coverage_score=score,
        breaking_count=breaking,
        warning_count=warning,
        summary=summary,
    )

    logger.info(
        f"[ContractAgent] Done  score={report.coverage_score:.0f}  "
        f"breaking={report.breaking_count}  warning={report.warning_count}"
    )
    return report


def _build_layers(ui_data, bff_data, engine_data, db_data) -> list[LayerContract]:
    return [
        LayerContract(
            layer="ui",
            fields=(
                ui_data.get("object_fields", [])
                + ui_data.get("chart_fields", [])
                + ui_data.get("table_columns", [])
                + ui_data.get("filter_keys", [])
            ),
            source_files=ui_data.get("source_files", []),
            notes=ui_data.get("notes", []),
        ),
        LayerContract(
            layer="bff",
            fields=bff_data.get("fields", []),
            source_files=bff_data.get("source_files", []),
            notes=bff_data.get("notes", []),
        ),
        LayerContract(
            layer="engine",
            fields=engine_data.get("fields", []),
            source_files=engine_data.get("source_files", []),
            notes=engine_data.get("notes", []),
        ),
        LayerContract(
            layer="db",
            fields=db_data.get("columns", []) + db_data.get("jsonb_columns", []),
            source_files=db_data.get("source_files", []),
            notes=db_data.get("notes", []),
        ),
    ]
