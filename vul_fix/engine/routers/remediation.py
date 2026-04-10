"""
VulFix remediation router — Ansible + Git pipeline.

POST /api/v1/vul-fix/remediate
  1. Validate inputs (scan_id format, git_repo_url scheme)
  2. Resolve GIT_TOKEN from environment only (never from request body)
  3. Load scan metadata + system context from vulnerability_db
  4. Load CVE findings grouped by package
  5. Clone org Ansible repo + analyse conventions
  6. For each package:
       a. Resolve hosts_pattern — Docker containers use 'all' by default
       b. Call Mistral AI → generate Ansible playbook YAML
       c. Validate: yamllint + ansible-lint (if available)
       d. Retry AI with error context on validation failure (max 2 retries)
  7. Build README.md
  8. Commit + push branch vulfix/{scan_id}, optionally create PR
  9. Return VulFixResponse with branch/PR URLs and per-package lint status

GET /api/v1/vul-fix/remediate/{scan_id}
  Returns scan metadata. Playbooks live in Git — no DB storage.

Security:
  - git_token sourced from GIT_TOKEN env var only (K8s secret)
  - scan_id validated by Pydantic before use in branch name
  - Concurrent request limit enforced via semaphore
  - No auto-execution — human review mandatory
"""

import asyncio
import logging
import os
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, status

from models.remediation import VulFixRequest, VulFixResponse, PlaybookResult
from db.fetcher import get_scan_info, get_scan_vulnerabilities, get_fixed_version
from core.ai_fixer import fix_package_ansible, _top_severity
from core.git_connector import GitConnector
from core.ansible_validator import validate_playbook
from core.git_pusher import GitPusher, build_readme

logger = logging.getLogger(__name__)
_audit = logging.getLogger("audit.vul_fix")
router = APIRouter()

# Max simultaneous remediation runs — each clones a repo + calls AI N times
_MAX_CONCURRENT    = int(os.getenv("VUL_FIX_MAX_CONCURRENT", "3"))
_semaphore         = asyncio.Semaphore(_MAX_CONCURRENT)

# Overall wall-clock limit per pipeline run (git clone + N×AI calls + git push).
# Prevents a hung Mistral or slow git from holding a semaphore slot indefinitely.
_PIPELINE_TIMEOUT  = int(os.getenv("VUL_FIX_PIPELINE_TIMEOUT", "600"))   # 10 min default

_MAX_RETRIES = 2   # AI self-correction retries per package on lint failure

# Env types that produce non-inventory hostnames (container IDs, pod names etc.)
_DYNAMIC_HOST_ENVS = {"docker", "container", "k8s", "kubernetes"}


# ── POST /remediate ───────────────────────────────────────────────────────────

@router.post("", response_model=VulFixResponse)
async def remediate(request: VulFixRequest, raw_req: Request):  # noqa: C901
    """
    Full pipeline: scan → AI Ansible playbooks → Git branch → PR.
    Review the PR before running any playbook.
    """
    # ── Audit log — record every remediation attempt ─────────────────────────
    client_ip = raw_req.client.host if raw_req.client else "unknown"
    _audit.info(
        "remediation_requested",
        extra={
            "audit":           True,
            "event":           "remediation_requested",
            "scan_id":         request.scan_id,
            "git_repo_url":    request.git_repo_url,
            "severity_filter": request.severity_filter,
            "create_pr":       request.create_pr,
            "client_ip":       client_ip,
        },
    )

    # ── Rate / concurrency gate ───────────────────────────────────────────────
    # asyncio.Semaphore.locked() is the public API — True when all slots are taken.
    # We do a non-blocking acquire attempt; if it fails the slot is truly full.
    if _semaphore.locked():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Too many concurrent remediation requests "
                f"(max={_MAX_CONCURRENT}). Retry shortly."
            ),
        )

    async with _semaphore:
        try:
            return await asyncio.wait_for(
                _run_pipeline(request, raw_req),
                timeout=_PIPELINE_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.error(
                f"[VulFix] Pipeline timed out after {_PIPELINE_TIMEOUT}s "
                f"for scan '{request.scan_id}'"
            )
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail=(
                    f"Pipeline timed out after {_PIPELINE_TIMEOUT}s. "
                    "Check Mistral API latency and git clone speed. "
                    f"Increase VUL_FIX_PIPELINE_TIMEOUT if needed."
                ),
            )


async def _run_pipeline(request: VulFixRequest, raw_req: Request) -> VulFixResponse:
    # ── 1. Resolve git token from env only ───────────────────────────────────
    git_token = os.getenv("GIT_TOKEN", "").strip()
    if not git_token:
        raise HTTPException(
            status_code=400,
            detail=(
                "GIT_TOKEN environment variable is not set. "
                "Configure it as a Kubernetes secret mounted into the container. "
                "Accepting tokens via the API is disabled for security reasons."
            ),
        )

    if not os.getenv("MISTRAL_API_KEY", "").strip():
        raise HTTPException(
            status_code=400,
            detail="MISTRAL_API_KEY is not set. Cannot generate Ansible playbooks.",
        )

    # ── 2. Load scan context from DB ─────────────────────────────────────────
    scan_info = get_scan_info(request.scan_id)
    if not scan_info:
        raise HTTPException(
            status_code=404,
            detail=f"Scan '{request.scan_id}' not found in vulnerability_db.",
        )

    agent_id     = scan_info.get("agent_id")
    vul_agent_id = scan_info.get("vul_agent_id")
    env_type     = scan_info.get("env_type", "unknown")
    platform     = scan_info.get("platform", "")
    hostname     = (scan_info.get("hostname") or
                    scan_info.get("system_info", {}).get("hostname", "unknown"))
    os_name      = scan_info.get("os_name", "")
    os_version   = scan_info.get("os_version", "")
    system_info  = scan_info.get("system_info") or {}
    os_label     = f"{os_name} {os_version}".strip() or platform or "linux"

    # ── 3. Resolve hosts_pattern ─────────────────────────────────────────────
    # Docker/K8s hostnames are container IDs / pod names — not valid inventory
    # hostnames. Default to 'all' unless caller explicitly overrides.
    if request.target_hosts_override:
        hosts_pattern = request.target_hosts_override
    elif any(k in env_type.lower() for k in _DYNAMIC_HOST_ENVS):
        hosts_pattern = "all"
        logger.info(
            f"[VulFix] env_type='{env_type}' detected — "
            f"overriding hosts pattern from '{hostname}' to 'all' "
            f"(container IDs are not valid Ansible inventory hostnames)"
        )
    else:
        hosts_pattern = hostname or "all"

    # ── 4. Load CVE findings ──────────────────────────────────────────────────
    findings = get_scan_vulnerabilities(
        request.scan_id,
        severity_filter=request.severity_filter,
    )
    if not findings:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No vulnerability findings for scan '{request.scan_id}' "
                f"(severity_filter={request.severity_filter})."
            ),
        )

    packages_map: dict  = defaultdict(list)
    severity_counts: dict = defaultdict(int)
    for f in findings:
        pkg = f.get("package_name") or "__unknown__"
        packages_map[pkg].append(f)
        sev = (f.get("severity") or "UNKNOWN").upper()
        severity_counts[sev] += 1

    logger.info(
        f"[VulFix] scan={request.scan_id}  findings={len(findings)}  "
        f"packages={len(packages_map)}  env={env_type}  os={os_label}  "
        f"hosts_pattern={hosts_pattern}  vul_agent={vul_agent_id}"
    )

    # ── 5. Clone + analyse Ansible repo ──────────────────────────────────────
    connector = GitConnector(
        repo_url=request.git_repo_url,
        token=git_token,
        base_branch=request.git_base_branch,
    )
    try:
        ansible_ctx = connector.analyze(hostname=hostname)
    except RuntimeError as e:
        # connector may have partially cloned — clean up before raising
        connector.cleanup()
        raise HTTPException(status_code=502, detail=f"Git clone/analysis failed: {e}")

    # ── 6. Generate + validate playbooks per package ──────────────────────────
    playbook_files: dict = {}
    playbook_results     = []

    try:
        for pkg_name, pkg_findings in packages_map.items():
            display_pkg = pkg_name if pkg_name != "__unknown__" else ""
            pkg_version = pkg_findings[0].get("package_version") or "unknown"
            fixed_hint  = get_fixed_version(display_pkg) if display_pkg else None
            cve_ids     = [f.get("cve_id", "") for f in pkg_findings]
            top_sev     = _top_severity(pkg_findings)
            top_cvss    = max(
                (float(f.get("cvss_v3_score") or f.get("score") or 0)
                 for f in pkg_findings),
                default=None,
            ) or None

            pb_filename  = f"patch_{display_pkg or 'unknown'}.yml"
            yaml_content = None
            lint_passed  = False
            lint_warnings= []
            error_msg    = None
            error_ctx    = None

            for attempt in range(1 + _MAX_RETRIES):
                try:
                    yaml_content = fix_package_ansible(
                        package_name=display_pkg,
                        package_version=pkg_version,
                        cves=pkg_findings,
                        ansible_ctx=ansible_ctx,
                        system_info=system_info,
                        platform=platform,
                        hostname=hostname,
                        fixed_version_hint=fixed_hint,
                        os_name=os_name,
                        os_version=os_version,
                        env_type=env_type,
                        hosts_pattern=hosts_pattern,
                        error_context=error_ctx,
                    )
                except Exception as e:
                    error_msg = str(e)
                    logger.error(
                        f"[VulFix] AI error for '{pkg_name}' "
                        f"(attempt {attempt + 1}/{1 + _MAX_RETRIES}): {e}"
                    )
                    break

                validation    = validate_playbook(yaml_content)
                lint_warnings = validation.warnings

                if validation.passed:
                    lint_passed = True
                    logger.info(
                        f"[VulFix] '{pkg_name}' playbook valid "
                        f"(attempt {attempt + 1}, "
                        f"{len(validation.warnings)} warning(s))"
                    )
                    break

                error_ctx = validation.as_error_context()
                logger.warning(
                    f"[VulFix] '{pkg_name}' lint failed "
                    f"(attempt {attempt + 1}): {validation.errors[:2]}"
                )
                if attempt == _MAX_RETRIES:
                    lint_warnings = validation.errors + validation.warnings
                    logger.warning(
                        f"[VulFix] '{pkg_name}': all retries exhausted — "
                        f"pushing with lint_passed=False for human review"
                    )

            if yaml_content:
                playbook_files[pb_filename] = yaml_content
            else:
                playbook_files[pb_filename] = _stub_playbook(
                    display_pkg, pkg_version, cve_ids, os_label, error_msg
                )

            playbook_results.append(PlaybookResult(
                package_name=display_pkg or "unknown",
                playbook_file=f"vulfix/{request.scan_id}/{pb_filename}",
                cve_ids=cve_ids,
                highest_severity=top_sev,
                highest_cvss=top_cvss,
                lint_passed=lint_passed,
                lint_warnings=lint_warnings[:10],
                error=error_msg,
            ))

        # ── 7. Build README ───────────────────────────────────────────────────
        pkg_summaries = [
            {
                "package":          r.package_name,
                "playbook_file":    r.playbook_file,
                "cves":             r.cve_ids,
                "highest_severity": r.highest_severity,
            }
            for r in playbook_results
        ]
        readme = build_readme(
            scan_id=request.scan_id,
            hostname=hostname,
            os_label=os_label,
            env_type=env_type,
            vul_agent_id=vul_agent_id,
            playbook_summaries=pkg_summaries,
            inventory_pattern=hosts_pattern,
            total_cves=len(findings),
            severity_counts=dict(severity_counts),
        )

        # ── 8. Commit + push branch ───────────────────────────────────────────
        n_crit   = severity_counts.get("CRITICAL", 0)
        pr_title = (
            f"[VulFix] {request.scan_id}: patch {len(packages_map)} package(s) "
            f"({n_crit} CRITICAL CVE{'s' if n_crit != 1 else ''})"
        )
        pr_body  = _build_pr_body(
            request.scan_id, hostname, os_label, env_type,
            vul_agent_id, findings, playbook_results, severity_counts,
        )

        pusher = GitPusher(
            connector=connector,
            scan_id=request.scan_id,
            token=git_token,
            repo_url=request.git_repo_url,
        )
        try:
            branch_url, pr_url = pusher.push_playbooks(
                playbook_files=playbook_files,
                readme_content=readme,
                pr_title=pr_title,
                pr_body=pr_body,
                create_pr=request.create_pr,
                base_branch=request.git_base_branch,
            )
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=f"Git push failed: {e}")

    finally:
        # Always clean up the temp clone regardless of success/failure
        connector.cleanup()

    branch_name = f"vulfix/{request.scan_id}"
    _log_summary(
        request.scan_id, hostname, os_label, env_type, hosts_pattern,
        branch_name, branch_url, pr_url, playbook_results,
        severity_counts, len(findings),
    )

    how_to_run = [
        f"1. Review the branch/PR: {pr_url or branch_url}",
        f"2. git fetch origin && git checkout {branch_name}",
        f"3. DRY-RUN (mandatory): ansible-playbook -i inventory/ "
        f"vulfix/{request.scan_id}/patch_<pkg>.yml --check --diff",
        f"4. After review and change-control approval: "
        f"ansible-playbook -i inventory/ vulfix/{request.scan_id}/patch_<pkg>.yml",
        f"5. Verify services are healthy, then merge the PR.",
    ]

    lint_ok  = sum(1 for r in playbook_results if r.lint_passed)
    lint_warn = len(playbook_results) - lint_ok
    msg = (
        f"Branch '{branch_name}' pushed with {len(playbook_results)} playbook(s). "
        f"Lint: {lint_ok} passed, {lint_warn} with warnings. "
        + (f"PR: {pr_url}" if pr_url else
           "No PR created (create_pr=false or token lacks PR permissions).")
        + " Review all playbooks before executing."
    )

    response = VulFixResponse(
        scan_id=request.scan_id,
        agent_id=agent_id,
        vul_agent_id=vul_agent_id,
        hostname=hostname,
        os_label=os_label,
        env_type=env_type,
        ansible_hosts_pattern=hosts_pattern,
        git_repo_url=request.git_repo_url,
        git_branch=branch_name,
        git_branch_url=branch_url,
        pr_url=pr_url,
        packages_processed=len(packages_map),
        total_cves=len(findings),
        severity_counts=dict(severity_counts),
        playbooks=playbook_results,
        how_to_run=how_to_run,
        message=msg,
    )

    # ── Audit log — completion record ─────────────────────────────────────────
    _audit.info(
        "remediation_completed",
        extra={
            "audit":            True,
            "event":            "remediation_completed",
            "scan_id":          request.scan_id,
            "git_branch":       branch_name,
            "pr_url":           pr_url,
            "packages":         len(packages_map),
            "total_cves":       len(findings),
            "severity_counts":  dict(severity_counts),
            "lint_passed":      sum(1 for r in playbook_results if r.lint_passed),
            "lint_warned":      sum(1 for r in playbook_results if not r.lint_passed),
        },
    )
    return response


# ── GET /remediate/{scan_id} ──────────────────────────────────────────────────

@router.get("/{scan_id}")
async def get_scan_status(scan_id: str):
    """Return scan metadata. Playbooks live in Git — check the branch."""
    # Validate scan_id format before DB query
    import re
    if not re.match(r'^[a-zA-Z0-9_-]{1,100}$', scan_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid scan_id format.",
        )

    scan_info = get_scan_info(scan_id)
    if not scan_info:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    os_name    = scan_info.get("os_name", "")
    os_version = scan_info.get("os_version", "")

    return {
        "scan_id":               scan_id,
        "agent_id":              scan_info.get("agent_id"),
        "vul_agent_id":          scan_info.get("vul_agent_id"),
        "hostname":              scan_info.get("hostname"),
        "os":                    f"{os_name} {os_version}".strip() or scan_info.get("platform"),
        "env_type":              scan_info.get("env_type"),
        "status":                scan_info.get("status"),
        "packages_scanned":      scan_info.get("packages_scanned"),
        "vulnerabilities_found": scan_info.get("vulnerabilities_found"),
        "note": (
            f"Playbooks are in Git branch 'vulfix/{scan_id}'. "
            "Use POST /remediate to generate if not yet done."
        ),
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _stub_playbook(
    pkg: str, version: str, cve_ids: list, os_label: str, error: Optional[str]
) -> str:
    """Minimal YAML stub committed when AI generation completely fails."""
    cve_str = ", ".join(cve_ids[:5])
    return (
        f"---\n"
        f"# VulFix GENERATION FAILED for package: {pkg}\n"
        f"# CVEs    : {cve_str}\n"
        f"# OS      : {os_label}\n"
        f"# Error   : {error or 'Unknown error'}\n"
        f"# Version : {version}\n"
        f"#\n"
        f"# ACTION REQUIRED: Manually create a playbook to upgrade '{pkg}'\n"
        f"# and address: {cve_str}\n"
        f"#\n"
        f"# Minimum template:\n"
        f"- name: \"MANUAL REVIEW REQUIRED: Patch {pkg}\"\n"
        f"  hosts: all\n"
        f"  become: true\n"
        f"  tasks:\n"
        f"    - name: Gather package facts\n"
        f"      ansible.builtin.package_facts:\n"
        f"        manager: auto\n"
        f"    - name: Upgrade {pkg}\n"
        f"      ansible.builtin.package:\n"
        f"        name: \"{pkg}\"\n"
        f"        state: latest\n"
        f"      tags: [security, patch]\n"
    )


def _build_pr_body(
    scan_id, hostname, os_label, env_type, vul_agent_id,
    findings, playbook_results, severity_counts,
) -> str:
    sc = dict(severity_counts)
    sev_table = "\n".join(
        f"| {s} | {sc.get(s, 0)} |"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )
    pb_table = "\n".join(
        f"| `{r.package_name}` | {r.highest_severity} "
        f"| {r.highest_cvss or 'N/A'} "
        f"| {'passed' if r.lint_passed else 'warnings'} "
        f"| `{r.playbook_file.split('/')[-1]}` |"
        for r in playbook_results
    )
    lint_issues = [
        f"- **{r.package_name}**: {'; '.join(r.lint_warnings[:3])}"
        for r in playbook_results if r.lint_warnings
    ]
    lint_section = (
        "\n### Lint Warnings (review before running)\n" + "\n".join(lint_issues)
        if lint_issues else ""
    )

    return (
        f"## VulFix Security Patch — Scan `{scan_id}`\n\n"
        f"> **DO NOT merge or run without reviewing all playbooks.**\n"
        f"> Run `--check` (dry-run) first. Execute only in an approved maintenance window.\n\n"
        f"### Target\n"
        f"| Field | Value |\n|-------|-------|\n"
        f"| Hostname | `{hostname}` |\n"
        f"| OS | {os_label} |\n"
        f"| Environment | {env_type} |\n"
        f"| User Agent | `{vul_agent_id or 'N/A'}` |\n"
        f"| Total CVEs | {len(findings)} |\n\n"
        f"### Severity Breakdown\n"
        f"| Severity | Count |\n|----------|-------|\n"
        f"{sev_table}\n\n"
        f"### Playbooks\n"
        f"| Package | Severity | CVSS | Lint | Playbook |\n"
        f"|---------|----------|------|------|----------|\n"
        f"{pb_table}\n"
        f"{lint_section}\n\n"
        f"### How to Run\n"
        f"```bash\n"
        f"# Step 1 — Dry run (mandatory)\n"
        f"ansible-playbook -i inventory/ vulfix/{scan_id}/patch_<package>.yml --check --diff\n\n"
        f"# Step 2 — Execute after approval\n"
        f"ansible-playbook -i inventory/ vulfix/{scan_id}/patch_<package>.yml\n"
        f"```\n\n"
        f"---\n"
        f"*Auto-generated by VulFix Engine v2. Human review required before execution.*\n"
    )


def _log_summary(
    scan_id, hostname, os_label, env_type, hosts_pattern,
    branch_name, branch_url, pr_url,
    playbook_results, severity_counts, total_cves,
) -> None:
    W  = 70
    sc = dict(severity_counts)
    lines = [
        "=" * W,
        "  VUL-FIX  ANSIBLE REMEDIATION COMPLETE",
        "=" * W,
        f"  Scan ID      : {scan_id}",
        f"  Host         : {hostname}",
        f"  OS           : {os_label}",
        f"  Env type     : {env_type}",
        f"  Hosts pattern: {hosts_pattern}",
        f"  Total CVEs   : {total_cves}",
        f"  CRITICAL: {sc.get('CRITICAL', 0)}  HIGH: {sc.get('HIGH', 0)}  "
        f"MEDIUM: {sc.get('MEDIUM', 0)}  LOW: {sc.get('LOW', 0)}",
        "",
        f"  Git branch   : {branch_name}",
        f"  Branch URL   : {branch_url or 'N/A'}",
        f"  PR URL       : {pr_url or 'N/A'}",
        "",
        "  Playbooks:",
    ]
    for r in playbook_results:
        lint_str = "lint:OK  " if r.lint_passed else "lint:WARN"
        err_str  = f"  ERROR: {r.error[:60]}" if r.error else ""
        lines.append(
            f"    [{r.highest_severity:8s}] {r.package_name:30s} "
            f"{lint_str}  {r.playbook_file.split('/')[-1]}{err_str}"
        )
    lines += [
        "",
        "  NEXT STEPS:",
        "  1. Open the PR and review every playbook carefully.",
        "  2. Run: ansible-playbook <playbook> --check --diff",
        "  3. Execute only in approved maintenance window.",
        "  4. Verify services are healthy, then merge the PR.",
        "=" * W,
    ]
    for line in lines:
        logger.info(line)
