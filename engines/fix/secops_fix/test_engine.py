"""
SecOps Fix Engine — Local Test Script
======================================
Run this to test the engine without starting the API server.

Usage:
  python test_engine.py                          # dry-run (no git patch)
  python test_engine.py --patch --token ghp_xxx  # also clone repo & push fix branch

What it does:
  1. Loads all 3330 fix rules
  2. Fetches real findings from DB for the latest scan
  3. Matches each finding to a rule (3-layer strategy)
  4. Generates fix suggestions
  5. Writes results to secops_remediation table in DB
  6. (Optional) Clones repo, patches offending lines, pushes secops-fix/<scan_id> branch
"""

import os, sys, argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "engine"))

# ── DB credentials ─────────────────────────────────────────────────────────
os.environ["SECOPS_DB_HOST"]     = "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
os.environ["SECOPS_DB_NAME"]     = "threat_engine_secops"
os.environ["SECOPS_DB_USER"]     = "postgres"
os.environ["SECOPS_DB_PASSWORD"] = "jtv2BkJF8qoFtAKP"

from core.rule_loader import rule_loader, KEYWORD_CONFIDENCE_THRESHOLD
from core.rule_matcher import match
from core.fix_generator import generate, generate_unmatched
from core import git_patcher
from db.fetcher import get_findings, get_scan_report
from db.writer import write_fix_result, mark_applied, mark_failed, get_remediation_summary


def run_test(scan_id: str, severity_filter=None, patch: bool = False,
             repo_token: str = None, max_findings: int = 50):

    # ── 1. Load rules ────────────────────────────────────────────────────────
    total_rules = rule_loader.load()
    print(f"\n{'='*65}")
    print(f"  SecOps Fix Engine — Test Run")
    print(f"{'='*65}")
    print(f"  Rules loaded     : {total_rules} across {len(rule_loader.category_counts)} categories")
    print(f"  Keyword threshold: {KEYWORD_CONFIDENCE_THRESHOLD}")
    print(f"  Patch mode       : {'YES — will push fix branch' if patch else 'NO  — dry-run only'}")

    # ── 2. Fetch scan report & findings ──────────────────────────────────────
    report = get_scan_report(scan_id)
    if not report:
        print(f"\n[ERROR] Scan not found: {scan_id}")
        sys.exit(1)

    findings = get_findings(scan_id, severity_filter=severity_filter)
    sample   = findings[:max_findings]

    print(f"\n  Scan             : {report.project_name}")
    print(f"  Repo             : {report.repo_url}")
    print(f"  Branch           : {report.branch}")
    print(f"  Total findings   : {report.total_findings}")
    print(f"  Testing on       : {len(sample)} findings (severity={severity_filter or 'all'})")
    print(f"{'='*65}\n")

    # ── 3. Clone repo read-only (to read original lines) ─────────────────────
    local_repo = None
    if patch and repo_token:
        try:
            print("  Cloning repo (read-only)...")
            local_repo = git_patcher.clone_readonly(report.repo_url, repo_token, report.branch)
            print(f"  Cloned to: {local_repo}\n")
        except Exception as e:
            print(f"  [WARN] Clone failed: {e} — fixes will use examples only\n")

    # ── 4. Match + Generate ───────────────────────────────────────────────────
    fix_branch  = f"secops-fix/{scan_id[:8]}"
    fix_results = []
    layer_counts = {"exact": 0, "cwe": 0, "category": 0, "regex": 0, "keyword": 0, "unmatched": 0}

    print(f"  {'#':>4}  {'SEV':8} {'LAYER':9} {'FILE':35} {'RULE_ID':45}  FIX")
    print(f"  {'-'*4}  {'-'*8} {'-'*9} {'-'*35} {'-'*45}  {'-'*30}")

    for i, finding in enumerate(sample, 1):
        rule, layer = match(finding)
        layer_counts[layer] += 1

        fix = generate(finding, rule, layer, local_repo) if rule else generate_unmatched(finding)
        fix_results.append(fix)

        # Write to DB
        try:
            write_fix_result(fix, fix_branch, report.repo_url)
        except Exception as e:
            pass  # table may not have pre-created rows in dry-run

        file_short  = (fix.file_path or "—")[-35:]
        rule_short  = (fix.rule_id or "—")[:45]
        fix_preview = ("✓ " + fix.suggested_fix[:28]) if fix.suggested_fix else ("? " + fix.fix_explanation[:28])
        print(f"  {i:>4}  {finding.severity:8} {layer:9} {file_short:35} {rule_short:45}  {fix_preview}")

    # ── 5. Summary ────────────────────────────────────────────────────────────
    matched   = len(sample) - layer_counts["unmatched"]
    patchable = sum(1 for f in fix_results if f.can_auto_patch)

    print(f"\n{'='*65}")
    print(f"  RESULTS ({len(sample)} findings tested)")
    print(f"{'='*65}")
    print(f"  Match rate       : {matched}/{len(sample)} ({matched/len(sample)*100:.0f}%)")
    print(f"  By layer         : {layer_counts}")
    print(f"  Auto-patchable   : {patchable} findings (have exact line rewrite)")
    print()

    # Show detailed fixes for first 3 matched findings
    shown = 0
    for fix in fix_results:
        if shown >= 3 or fix.match_layer == "unmatched":
            continue
        print(f"  -- Fix Detail #{shown+1} {'--'*30}")
        print(f"  File        : {fix.file_path}:{fix.line_number}")
        print(f"  Rule        : {fix.matched_rule_id}  [{fix.match_layer}]")
        print(f"  Severity    : {fix.severity}")
        if fix.original_code:
            print(f"  Original    : {fix.original_code.strip()}")
        if fix.suggested_fix:
            print(f"  Fix         : {fix.suggested_fix.strip()}")
        if fix.compliant_example:
            print(f"  Example     : {fix.compliant_example[:120]}")
        print(f"  Explanation : {fix.fix_explanation[:200]}")
        if fix.references:
            print(f"  Reference   : {fix.references[0]}")
        print()
        shown += 1

    # ── 6. Git patch (optional) ───────────────────────────────────────────────
    pushed_branch = None
    if patch and repo_token and patchable > 0:
        print(f"  Applying {patchable} auto-patches and pushing branch '{fix_branch}'...")
        try:
            pushed_branch, _, patched_count = git_patcher.apply_fixes(
                repo_url=report.repo_url,
                repo_token=repo_token,
                secops_scan_id=scan_id,
                source_branch=report.branch,
                fix_results=fix_results,
            )
            if pushed_branch:
                print(f"\n  [SUCCESS] Fix branch pushed: {pushed_branch}")
                print(f"  [SUCCESS] {patched_count} files patched")
                print(f"  [NEXT]    Review & merge at: {report.repo_url}/compare/{pushed_branch}")
                for fix in fix_results:
                    if fix.can_auto_patch:
                        mark_applied(fix.finding_id, pushed_branch)
            else:
                print("  [INFO] No auto-patchable fixes were applied.")
        except Exception as e:
            print(f"  [ERROR] Git patch failed: {e}")
            for fix in fix_results:
                if fix.can_auto_patch:
                    mark_failed(fix.finding_id, str(e))
    elif patch and patchable == 0:
        print("  [INFO] No auto-patchable findings — fix branch not created.")
        print("         (Fixes require the engine to read the original source line.)")

    # Cleanup
    if local_repo:
        git_patcher.cleanup(local_repo)

    # ── 7. Final quick-view summary card ─────────────────────────────────────
    db_summary = {}
    try:
        db_summary = get_remediation_summary(scan_id)
    except Exception:
        pass

    applied_fixes   = [f for f in fix_results if f.can_auto_patch]
    generated_fixes = [f for f in fix_results if not f.can_auto_patch and f.match_layer != "unmatched"]
    unmatched_fixes = [f for f in fix_results if f.match_layer == "unmatched"]

    print(f"\n{'='*65}")
    print(f"  REMEDIATION QUICK-VIEW SUMMARY")
    print(f"{'='*65}")
    print(f"  Scan ID          : {scan_id}")
    print(f"  Project          : {report.project_name}")
    print(f"  Repo             : {report.repo_url}")
    print(f"  Findings tested  : {len(sample)}  (severity={severity_filter or 'all'})")
    print(f"  Match rate       : {matched}/{len(sample)} ({matched/len(sample)*100:.0f}%)")
    print(f"  By layer         : exact={layer_counts['exact']}  cwe={layer_counts['cwe']}  "
          f"category={layer_counts['category']}  regex={layer_counts['regex']}  "
          f"keyword={layer_counts['keyword']}  unmatched={layer_counts['unmatched']}")
    print(f"")
    print(f"  AUTO-PATCHED  ({len(applied_fixes)} findings — committed to fix branch)")
    if applied_fixes:
        for f in applied_fixes:
            orig = (f.original_code or "").strip()[:50]
            fix  = (f.suggested_fix or "").strip()[:50]
            print(f"    {f.file_path}:{f.line_number:<5}  {orig!r:52}  ->  {fix!r}")
    else:
        print(f"    (none)")
    print(f"")
    print(f"  FIX GENERATED ({len(generated_fixes)} findings — in DB, needs manual review)")
    for f in generated_fixes[:10]:
        rule_short = (f.matched_rule_id or "")[:40]
        expl = (f.fix_explanation or "")[:60].replace("\n", " ")
        print(f"    {f.file_path}:{str(f.line_number or ''):<5}  [{rule_short}]  {expl}")
    if len(generated_fixes) > 10:
        print(f"    ... and {len(generated_fixes)-10} more — query DB for full list")
    print(f"")
    print(f"  UNMATCHED     ({len(unmatched_fixes)} findings — no rule found)")
    print(f"")
    if pushed_branch:
        print(f"  GIT FIX BRANCH   : {pushed_branch}")
        print(f"  REVIEW & MERGE   : {report.repo_url}/compare/{pushed_branch}")
    elif patch:
        print(f"  GIT              : No auto-patchable findings — branch not created")
    else:
        print(f"  GIT              : Dry-run — use --patch --token <PAT> to push fixes")
    print(f"")
    if db_summary:
        print(f"  DB STATUS  (secops_remediation table)")
        print(f"    total={db_summary.get('total',0)}  "
              f"applied={db_summary.get('applied',0)}  "
              f"fix_generated={db_summary.get('fix_generated',0)}  "
              f"matched={db_summary.get('matched',0)}  "
              f"skipped={db_summary.get('skipped',0)}  "
              f"failed={db_summary.get('failed',0)}")
    print(f"  DB QUERY   : SELECT * FROM secops_remediation")
    print(f"               WHERE secops_scan_id = '{scan_id}';")
    print(f"{'='*65}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecOps Fix Engine test runner")
    parser.add_argument("--scan-id",  default="7f1c6e8f-1b3a-45b1-b57b-e1c8addd4315",
                        help="secops_scan_id to test (default: threat-engine SAST scan)")
    parser.add_argument("--severity", default=None,
                        help="Comma-separated severities: critical,high,medium,low")
    parser.add_argument("--max",      type=int, default=50,
                        help="Max findings to test (default: 50)")
    parser.add_argument("--patch",    action="store_true",
                        help="Clone repo and push a secops-fix branch with changes")
    parser.add_argument("--token",    default=None,
                        help="GitHub PAT with write access to the repo (required for --patch)")
    args = parser.parse_args()

    severity_filter = [s.strip() for s in args.severity.split(",")] if args.severity else None

    run_test(
        scan_id=args.scan_id,
        severity_filter=severity_filter,
        patch=args.patch,
        repo_token=args.token,
        max_findings=args.max,
    )
