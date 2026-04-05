"""
Remediation router — the core engine endpoint.

POST /api/v1/secops-fix/remediate
  - Fetches findings from DB (SAST already matched rules — no re-matching needed)
  - For each finding: direct lookup of rule metadata for AI hints (O(1))
  - Groups findings per file, calls Mistral AI once per file with full code context
  - Commits AI-fixed files to a new fix branch and pushes to origin
  - Writes all results to DB

GET  /api/v1/secops-fix/remediate/{secops_scan_id}
  - Returns remediation status and summary for a completed run
"""

import logging
import os
from typing import Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks

from models.remediation import RemediationRequest, RemediationSummary, RemediationStatus
from models.fix_result import FixResult
from db.fetcher import get_findings, get_scan_report, get_rule_metadata_batch
from db.writer import (
    init_remediation_rows, write_fix_result,
    mark_applied, mark_failed, get_remediation_summary,
)
from core import git_patcher
from core import ai_fixer

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("", response_model=RemediationSummary)
async def remediate(request: RemediationRequest, background_tasks: BackgroundTasks):
    """
    Trigger AI-powered remediation for a completed secops scan.

    The SAST scanner already:
      - Identified which rule fired (rule_id stored in finding)
      - Recorded file, line, message, severity, language, CWE

    So this engine does NOT re-match rules. Instead it:
      1. Fetches findings from DB.
      2. Direct O(1) lookup of rule metadata (compliant example) as AI hint.
      3. Clones repo to read actual source code.
      4. Groups findings per file → one Mistral call per file with full code context.
      5. Writes AI-corrected files back → commits → pushes fix branch.
    """
    scan_report = get_scan_report(request.secops_scan_id)
    if not scan_report:
        raise HTTPException(
            status_code=404,
            detail=f"Scan not found: {request.secops_scan_id}",
        )

    findings = get_findings(
        request.secops_scan_id,
        severity_filter=request.severity_filter,
    )
    if not findings:
        return RemediationSummary(
            secops_scan_id=request.secops_scan_id,
            total_findings=0, matched=0, fix_generated=0,
            applied=0, failed=0, skipped=0,
            fix_branch=None, pr_url=None, remediations=[],
        )

    fix_branch = f"secops-fix/{request.secops_scan_id[:8]}"

    # Pre-create pending rows so status is visible immediately
    init_remediation_rows(request, len(findings), fix_branch, scan_report)

    # Clone repo once — used for both reading source code (AI context) and writing fixes
    local_repo_path = None
    try:
        local_repo_path = git_patcher.clone_readonly(
            repo_url=scan_report.repo_url,
            repo_token=request.repo_token,
            source_branch=scan_report.branch,
        )
    except Exception as e:
        logger.warning(f"Could not clone repo: {e} — AI fix requires source code, skipping")

    try:
        # ── Batch-fetch rule metadata from DB (single round-trip) ─────────────
        # secops_rule_metadata is the single source of truth — same table the
        # SAST scanner seeds from its JSON docs. No duplicate JSON files needed.
        unique_rule_ids = list({f.rule_id for f in findings if f.rule_id})
        rules_cache = get_rule_metadata_batch(unique_rule_ids)
        logger.info(
            f"Rule metadata: {len(rules_cache)}/{len(unique_rule_ids)} "
            f"rule_ids resolved from secops_rule_metadata"
        )

        # ── Build fix result stubs from findings ──────────────────────────────
        # No rule re-matching — SAST already identified rule_id.
        # rules_cache used only to pull compliant_example + description as AI hints.
        fix_results = []
        for finding in findings:
            try:
                rule = rules_cache.get((finding.rule_id or "").lower())
                fix = _build_fix_result(finding, rule, fix_branch)
                fix_results.append(fix)
                write_fix_result(fix, fix_branch, scan_report.repo_url)
            except Exception as e:
                logger.error(f"Error building fix result for finding {finding.id}: {e}")
                mark_failed(finding.id, str(e)[:1024])

        # ── AI per-file fix (Mistral) ─────────────────────────────────────────
        # Group findings by file → one API call per file with full file content.
        # Peer's approach from safepatch_engine.py: send full file + all findings,
        # get back corrected full file. AI sees imports, class structure, context.
        ai_corrected_files = {}  # {rel_path: corrected_content}

        if local_repo_path:
            files_map: dict = {}
            for fix in fix_results:
                if fix.file_path:
                    files_map.setdefault(fix.file_path, []).append(fix)

            for rel_path, fixes_for_file in files_map.items():
                full_path = os.path.realpath(
                    os.path.join(local_repo_path, rel_path.lstrip("/\\"))
                )
                if not os.path.isfile(full_path):
                    logger.warning(f"[AI] File not found in repo: {rel_path}")
                    continue
                try:
                    with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                        original_content = fh.read()
                except Exception as e:
                    logger.warning(f"[AI] Cannot read {rel_path}: {e}")
                    continue

                # Build AI hint list — line + message + compliant example per finding
                ai_findings = []
                for fix in fixes_for_file:
                    ai_findings.append({
                        "line":              fix.line_number or 0,
                        "message":           fix.fix_explanation or "",
                        "rule_id":           fix.rule_id or "",
                        "recommendation":    fix.fix_explanation or "",
                        "compliant_example": fix.compliant_example or "",
                    })

                language = (fixes_for_file[0].language or "").lower() or "code"
                corrected = ai_fixer.fix_file(original_content, ai_findings, language)

                if corrected and corrected != original_content:
                    ai_corrected_files[rel_path] = corrected
                    for fix in fixes_for_file:
                        fix.can_auto_patch = True
                    logger.info(
                        f"[AI] Fix generated for {rel_path} "
                        f"({len(fixes_for_file)} finding(s))"
                    )
                else:
                    logger.info(f"[AI] No change for {rel_path}")

        # ── Push fix branch ───────────────────────────────────────────────────
        pushed_branch = None
        if ai_corrected_files or any(f.can_auto_patch for f in fix_results):
            try:
                pushed_branch, _, patched_count = git_patcher.apply_fixes(
                    repo_url=scan_report.repo_url,
                    repo_token=request.repo_token,
                    secops_scan_id=request.secops_scan_id,
                    source_branch=scan_report.branch,
                    fix_results=fix_results,
                    ai_corrected_files=ai_corrected_files,
                )
                if pushed_branch:
                    for fix in fix_results:
                        if fix.can_auto_patch:
                            mark_applied(fix.finding_id, pushed_branch)
            except Exception as e:
                logger.error(f"Git patch failed: {e}")
                for fix in fix_results:
                    if fix.can_auto_patch:
                        mark_failed(fix.finding_id, f"git_patch: {str(e)[:512]}")
        else:
            logger.info("No patchable fixes — fix branch not created")

    finally:
        if local_repo_path:
            git_patcher.cleanup(local_repo_path)

    # ── Build response ────────────────────────────────────────────────────────
    summary_db = get_remediation_summary(request.secops_scan_id)
    remediations = _build_statuses(fix_results, pushed_branch)

    result = RemediationSummary(
        secops_scan_id=request.secops_scan_id,
        total_findings=len(findings),
        matched=len(fix_results),
        fix_generated=summary_db.get("fix_generated", 0),
        applied=summary_db.get("applied", 0),
        failed=summary_db.get("failed", 0),
        skipped=summary_db.get("skipped", 0),
        fix_branch=pushed_branch,
        pr_url=None,
        remediations=remediations,
    )
    _log_summary(result, scan_report, fix_results)
    return result


@router.get("/{secops_scan_id}", response_model=RemediationSummary)
async def get_remediation_status(secops_scan_id: str):
    """Return remediation status for a previously triggered scan."""
    scan_report = get_scan_report(secops_scan_id)
    if not scan_report:
        raise HTTPException(status_code=404, detail=f"Scan not found: {secops_scan_id}")

    summary_db = get_remediation_summary(secops_scan_id)
    if not summary_db:
        raise HTTPException(
            status_code=404,
            detail=f"No remediation found for scan {secops_scan_id}. Trigger POST /remediate first.",
        )

    return RemediationSummary(
        secops_scan_id=secops_scan_id,
        total_findings=summary_db.get("total", 0),
        matched=summary_db.get("matched", 0),
        fix_generated=summary_db.get("fix_generated", 0),
        applied=summary_db.get("applied", 0),
        failed=summary_db.get("failed", 0),
        skipped=summary_db.get("skipped", 0),
        fix_branch=summary_db.get("fix_branch"),
        pr_url=summary_db.get("pr_url"),
        remediations=[],
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_fix_result(finding, rule: Optional[dict], fix_branch: str) -> FixResult:
    """
    Build a FixResult directly from the SAST finding + optional rule metadata hint.

    No rule re-matching needed — the SAST already identified rule_id.
    Rule metadata (compliant_example, description) is fetched from secops_rule_metadata
    purely as hints to pass to Mistral AI.
    """
    compliant_example = None
    fix_explanation = finding.message or f"Security issue: {finding.rule_id}"
    references = None

    if rule:
        # Pull compliant example — prefer language-matched one
        examples = (rule.get("examples") or {}).get("compliant") or []
        if examples:
            lang = (finding.language or "").lower()
            compliant_example = _pick_compliant_example(examples, lang)

        # Build explanation from rule metadata
        parts = []
        if rule.get("title"):
            parts.append(f"Issue: {rule['title']}.")
        if rule.get("description"):
            sentences = rule["description"].strip().split(". ")
            parts.append(". ".join(sentences[:2]))
        if rule.get("recommendation"):
            parts.append(f"Fix: {rule['recommendation']}")
        if rule.get("impact"):
            parts.append(f"Impact: {rule['impact']}")
        if parts:
            fix_explanation = "\n".join(parts)

        references = rule.get("references")

    return FixResult(
        finding_id=finding.id,
        secops_scan_id=finding.secops_scan_id,
        rule_id=finding.rule_id,
        matched_rule_id=rule.get("rule_id") if rule else None,
        match_layer="direct" if rule else "no_rule_metadata",
        file_path=finding.file_path,
        line_number=finding.line_number,
        language=finding.language,
        severity=finding.severity,
        original_code=None,        # Read from repo by AI fixer — not needed here
        suggested_fix=None,        # AI generates the fix — not needed here
        fix_explanation=fix_explanation,
        compliant_example=compliant_example,
        references=references,
        can_auto_patch=False,      # Will be set True by AI fixer if it succeeds
    )


def _pick_compliant_example(examples: list, language: str) -> Optional[str]:
    """Return the most relevant compliant example for the language."""
    str_examples = [str(ex) for ex in examples if ex]
    if not str_examples:
        return None
    if not language:
        return str_examples[0]
    for ex in str_examples:
        ex_l = ex.lower()
        if language == "python" and ("os.getenv" in ex_l or "os.environ" in ex_l):
            return ex
        if language in ("javascript", "typescript") and "process.env" in ex_l:
            return ex
        if language == "java" and "system.getenv" in ex_l:
            return ex
        if language == "go" and "os.getenv" in ex_l:
            return ex
        if language == "ruby" and "env[" in ex_l:
            return ex
    return str_examples[0]


def _log_summary(summary, scan_report, fix_results) -> None:
    W = 65
    patched   = [f for f in fix_results if f.can_auto_patch]
    guidance  = [f for f in fix_results if not f.can_auto_patch and f.match_layer != "no_rule_metadata"]
    no_meta   = [f for f in fix_results if f.match_layer == "no_rule_metadata"]
    ai_mode   = os.getenv("MISTRAL_API_KEY", "").strip() != ""

    lines = [
        "=" * W,
        "  SECOPS-FIX  REMEDIATION SUMMARY",
        "=" * W,
        f"  Scan ID      : {summary.secops_scan_id}",
        f"  Project      : {scan_report.project_name}",
        f"  Repo         : {scan_report.repo_url}",
        f"  Fix mode     : {'Mistral AI (full-file context)' if ai_mode else 'Guidance only (set MISTRAL_API_KEY to enable AI)'}",
        f"  Findings     : {summary.total_findings} processed",
        "",
        f"  AUTO-PATCHED   : {summary.applied}  (committed to fix branch)",
    ]
    for f in patched:
        lines.append(f"    {f.file_path}:{f.line_number}  [{f.rule_id}]")

    lines += [
        "",
        f"  FIX GUIDANCE   : {len(guidance)}  (in DB — compliant example available)",
    ]
    for f in guidance[:8]:
        lines.append(f"    {f.file_path}:{f.line_number}  [{f.rule_id}]")
    if len(guidance) > 8:
        lines.append(f"    ... and {len(guidance) - 8} more")

    lines += [
        "",
        f"  NO RULE META   : {len(no_meta)}  (rule_id not in docs — AI used finding message only)",
        f"  FAILED         : {summary.failed}",
        "",
    ]
    if summary.fix_branch:
        lines.append(f"  FIX BRANCH     : {summary.fix_branch}")
        lines.append(f"  REVIEW AT      : {scan_report.repo_url}/compare/{summary.fix_branch}")
    else:
        lines.append("  FIX BRANCH     : not created (no patchable findings or MISTRAL_API_KEY not set)")
    lines += [
        "",
        f"  DB TABLE       : secops_remediation",
        f"  DB QUERY       : SELECT * FROM secops_remediation",
        f"                   WHERE secops_scan_id = '{summary.secops_scan_id}';",
        "=" * W,
    ]
    for line in lines:
        logger.info(line)


def _build_statuses(fix_results, fix_branch):
    statuses = []
    for fix in fix_results:
        if fix.can_auto_patch:
            status = "applied" if fix_branch else "fix_generated"
        else:
            status = "fix_generated"

        statuses.append(RemediationStatus(
            remediation_id="",
            secops_scan_id=fix.secops_scan_id,
            finding_id=fix.finding_id,
            rule_id=fix.rule_id,
            file_path=fix.file_path,
            line_number=fix.line_number,
            match_layer=fix.match_layer,
            status=status,
            fix_branch=fix_branch if fix.can_auto_patch else None,
            pr_url=None,
            error_message=None,
            created_at=None,
        ))
    return statuses
