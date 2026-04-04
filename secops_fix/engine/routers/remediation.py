"""
Remediation router — the core engine endpoint.

POST /api/v1/secops-fix/remediate
  - Fetches findings from DB for the scan
  - Matches each finding to a rule (3-layer)
  - Generates a fix suggestion
  - Clones the repo, applies auto-patchable fixes, pushes a fix branch
  - Writes all results back to DB

GET  /api/v1/secops-fix/remediate/{secops_scan_id}
  - Returns remediation status and summary for a completed run
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks

from models.remediation import RemediationRequest, RemediationSummary, RemediationStatus
from db.fetcher import get_findings, get_scan_report
from db.writer import (
    init_remediation_rows, write_fix_result,
    mark_applied, mark_failed, get_remediation_summary,
)
from core.rule_matcher import match
from core.fix_generator import generate, generate_unmatched
from core import git_patcher

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("", response_model=RemediationSummary)
async def remediate(request: RemediationRequest, background_tasks: BackgroundTasks):
    """
    Trigger remediation for a completed secops scan.

    Steps:
      1. Validate scan exists in DB.
      2. Fetch findings (optionally filtered by severity).
      3. Clone repo (read-only) to read original source lines.
      4. Match each finding → rule (3-layer strategy).
      5. Generate fix for each matched finding.
      6. Write fix results to DB (secops_remediation table).
      7. Apply auto-patchable fixes, push fix branch to repo.
      8. Update DB with applied/failed status.
      9. Return full summary.
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

    # Clone repo read-only to read original lines for fix generation
    local_repo_path = None
    try:
        local_repo_path = git_patcher.clone_readonly(
            repo_url=scan_report.repo_url,
            repo_token=request.repo_token,
            source_branch=scan_report.branch,
        )
    except Exception as e:
        logger.warning(f"Could not clone repo for line reading: {e} — fixes will use examples only")

    # ── Match + Generate ──────────────────────────────────────────────────────
    fix_results = []
    for finding in findings:
        try:
            rule, layer = match(finding)
            if rule:
                fix = generate(finding, rule, layer, local_repo_path)
            else:
                fix = generate_unmatched(finding)
            fix_results.append(fix)
            write_fix_result(fix, fix_branch, scan_report.repo_url)
        except Exception as e:
            logger.error(f"Error processing finding {finding.id}: {e}")
            mark_failed(finding.id, str(e))

    # ── Apply patches + push branch ───────────────────────────────────────────
    pushed_branch = None
    if any(f.can_auto_patch for f in fix_results):
        try:
            pushed_branch, _, patched_count = git_patcher.apply_fixes(
                repo_url=scan_report.repo_url,
                repo_token=request.repo_token,
                secops_scan_id=request.secops_scan_id,
                source_branch=scan_report.branch,
                fix_results=fix_results,
            )
            if pushed_branch:
                for fix in fix_results:
                    if fix.can_auto_patch and fix.suggested_fix:
                        mark_applied(fix.finding_id, pushed_branch)
        except Exception as e:
            logger.error(f"Git patch failed: {e}")
            for fix in fix_results:
                if fix.can_auto_patch:
                    mark_failed(fix.finding_id, f"git_patch: {e}")
    else:
        logger.info("No auto-patchable fixes in this scan — fix branch not created")

    # Cleanup clone
    if local_repo_path:
        git_patcher.cleanup(local_repo_path)

    # ── Build response ────────────────────────────────────────────────────────
    summary_db = get_remediation_summary(request.secops_scan_id)
    remediations = _build_statuses(fix_results, pushed_branch)

    return RemediationSummary(
        secops_scan_id=request.secops_scan_id,
        total_findings=len(findings),
        matched=summary_db.get("matched", 0),
        fix_generated=summary_db.get("fix_generated", 0),
        applied=summary_db.get("applied", 0),
        failed=summary_db.get("failed", 0),
        skipped=summary_db.get("skipped", 0),
        fix_branch=pushed_branch,
        pr_url=None,    # Future: auto-raise PR via GitHub API
        remediations=remediations,
    )


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

def _build_statuses(fix_results, fix_branch):
    statuses = []
    for fix in fix_results:
        if fix.match_layer == "unmatched":
            status = "skipped"
        elif fix.can_auto_patch:
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
