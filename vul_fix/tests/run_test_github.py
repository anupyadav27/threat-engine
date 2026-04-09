"""
VulFix End-to-End Test -- REAL GitHub repo, real DB + real Mistral AI.

Fires the full pipeline against https://github.com/ajaylgtech/vulfix-ansible-demo
and creates an actual GitHub PR with the generated Ansible playbooks.

Steps:
  0 : Drop legacy vul_remediation table (one-time cleanup)
  1 : Load real scan + CVE findings from vulnerability_db
  2 : Clone + analyse the real GitHub Ansible repo (GitConnector)
  3 : Call Mistral AI -- generate Ansible playbook per package (with retry)
  4 : Validate with yamllint / ansible-lint
  5 : Push branch vulfix/{scan_id} to GitHub, open PR
  6 : Print PR URL + generated playbook content

Usage:
  cd vul_fix/engine
  python ../tests/run_test_github.py [scan_id]
  e.g. python ../tests/run_test_github.py 15032026_017

Requirements:
  - engine/.env must contain GIT_TOKEN (GitHub PAT with repo scope)
  - engine/.env must contain MISTRAL_API_KEY
  - GIT_REPO_URL env var or default below
"""

import os
import sys
from pathlib import Path

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# -- Add engine to path -------------------------------------------------------
ENGINE_DIR = Path(__file__).parent.parent / "engine"
sys.path.insert(0, str(ENGINE_DIR))

# Load .env from engine dir
_env_file = ENGINE_DIR / ".env"
if _env_file.exists():
    from dotenv import load_dotenv
    load_dotenv(_env_file)
    print(f"[Test] Loaded .env from {_env_file}")
else:
    print(f"[WARN] No .env found at {_env_file} -- relying on shell environment")

# -- Logging ------------------------------------------------------------------
import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("vulfixtest")

# -- Test config --------------------------------------------------------------
SCAN_ID      = sys.argv[1] if len(sys.argv) > 1 else "15032026_017"
MAX_PACKAGES = 2        # limit AI calls; set higher to test all packages
SEV_FILTER   = ["CRITICAL", "HIGH"]

# Real GitHub repo created for this test
GIT_REPO_URL = os.getenv("GIT_REPO_URL",
                          "https://github.com/ajaylgtech/vulfix-ansible-demo.git")
BASE_BRANCH  = "main"

# PR creation: set to False to just push the branch without opening a PR
CREATE_PR    = True


# =============================================================================
# Preflight checks
# =============================================================================
def preflight():
    print("\n" + "#"*60)
    print("  VUL-FIX  GITHUB END-TO-END TEST")
    print("#"*60)
    print(f"  Scan ID      : {SCAN_ID}")
    print(f"  Max packages : {MAX_PACKAGES}")
    print(f"  Sev filter   : {SEV_FILTER}")
    print(f"  Git repo     : {GIT_REPO_URL}")
    print(f"  Create PR    : {CREATE_PR}")

    git_token = os.getenv("GIT_TOKEN", "").strip()
    mistral_key = os.getenv("MISTRAL_API_KEY", "").strip()
    api_key = os.getenv("VUL_FIX_API_KEY", "").strip()

    masked_token = ("*" * max(len(git_token) - 4, 0) + git_token[-4:]) if git_token else "NOT SET"
    print(f"\n  GIT_TOKEN    : {masked_token}")
    print(f"  MISTRAL_KEY  : {'SET [OK]' if mistral_key else 'NOT SET [ERROR]'}")
    print(f"  API_KEY      : {'SET [OK]' if api_key else 'test-api-key-local (default)'}")

    errors = []
    if not git_token:
        errors.append("GIT_TOKEN is not set. Add it to engine/.env")
    if not mistral_key:
        errors.append("MISTRAL_API_KEY is not set. Add it to engine/.env")

    if errors:
        print("\n[ERROR] Preflight failed:")
        for e in errors:
            print(f"  - {e}")
        raise SystemExit(1)

    # Ensure VUL_FIX_API_KEY is set (needed for middleware if server is started)
    if not api_key:
        os.environ["VUL_FIX_API_KEY"] = "test-api-key-local"

    print("\n  [OK] All preflight checks passed.\n")
    return git_token


# =============================================================================
# STEP 0 -- Drop legacy table
# =============================================================================
def step0_drop_table():
    print("\n" + "="*60)
    print("STEP 0 -- Drop legacy vul_remediation table")
    print("="*60)
    from db.writer import drop_remediation_table
    try:
        dropped = drop_remediation_table()
        if dropped:
            print("  [DROPPED]  vul_remediation table removed from DB.")
        else:
            print("  [SKIP]     vul_remediation table did not exist.")
    except Exception as e:
        print(f"  [WARN]     Drop failed (non-fatal): {e}")


# =============================================================================
# STEP 1 -- Load scan from real DB
# =============================================================================
def step1_load_scan(scan_id):
    print("\n" + "="*60)
    print(f"STEP 1 -- Load scan {scan_id} from vulnerability_db")
    print("="*60)

    from db.fetcher import get_scan_info, get_scan_vulnerabilities, get_fixed_version
    from collections import defaultdict

    scan_info = get_scan_info(scan_id)
    if not scan_info:
        raise SystemExit(f"  [ERROR] Scan not found: {scan_id}")

    os_name    = scan_info.get("os_name", "")
    os_version = scan_info.get("os_version", "")
    env_type   = scan_info.get("env_type", "unknown")
    hostname   = (scan_info.get("hostname") or
                  scan_info.get("system_info", {}).get("hostname", "unknown"))

    print(f"  Scan ID      : {scan_id}")
    print(f"  Agent ID     : {scan_info.get('agent_id')}")
    print(f"  Vul Agent ID : {scan_info.get('vul_agent_id')}")
    print(f"  Hostname     : {hostname}")
    print(f"  OS           : {os_name} {os_version}")
    print(f"  Env type     : {env_type}")
    print(f"  Status       : {scan_info.get('status')}")
    print(f"  Packages     : {scan_info.get('packages_scanned')}")
    print(f"  CVEs found   : {scan_info.get('vulnerabilities_found')}")

    findings = get_scan_vulnerabilities(scan_id, severity_filter=SEV_FILTER)
    print(f"\n  Findings loaded : {len(findings)} (filter: {SEV_FILTER})")

    packages_map = defaultdict(list)
    for f in findings:
        pkg = f.get("package_name") or "__unknown__"
        packages_map[pkg].append(f)

    def pkg_score(items):
        return max((float(i.get("cvss_v3_score") or i.get("score") or 0)
                    for i in items), default=0)

    top_pkgs = sorted(packages_map.items(),
                      key=lambda x: pkg_score(x[1]), reverse=True)[:MAX_PACKAGES]

    print(f"\n  Top {len(top_pkgs)} package(s) selected (MAX_PACKAGES={MAX_PACKAGES}):")
    for pkg, cves in top_pkgs:
        severities = {c.get("severity", "?") for c in cves}
        top_score  = pkg_score(cves)
        print(f"    - {pkg:30s} {len(cves)} CVEs  sev={severities}  max_cvss={top_score}")

    return scan_info, dict(top_pkgs), get_fixed_version


# =============================================================================
# STEP 2 -- Clone + analyse GitHub Ansible repo
# =============================================================================
def step2_analyse_repo(git_token, hostname):
    print("\n" + "="*60)
    print("STEP 2 -- Clone + analyse GitHub Ansible repo")
    print("="*60)
    print(f"  Repo    : {GIT_REPO_URL}")
    print(f"  Branch  : {BASE_BRANCH}")
    print(f"  Host    : {hostname}")

    from core.git_connector import GitConnector
    connector = GitConnector(
        repo_url=GIT_REPO_URL,
        token=git_token,
        base_branch=BASE_BRANCH,
    )
    ctx = connector.analyze(hostname=hostname)

    print(f"\n  Structure      : {ctx.structure_type}")
    print(f"  Ansible ver    : {ctx.ansible_version or 'not detected (will use FQCN)'}")
    print(f"  FQCN required  : {ctx.fqcn_required}")
    print(f"  Become method  : {ctx.become_method}")
    print(f"  Remote user    : {ctx.remote_user or '(Ansible default)'}")
    print(f"  Existing roles : {ctx.existing_roles}")
    print(f"  Inventory group: {ctx.inventory_group}")
    print(f"  Has vault      : {ctx.has_vault}")
    print(f"\n  Package task snippet (first 10 lines):")
    for line in ctx.package_task_snippet.splitlines()[:10]:
        print(f"    {line}")

    return connector, ctx


# =============================================================================
# STEP 3+4 -- Generate + validate playbooks
# =============================================================================
def step3_generate_playbooks(scan_info, packages_map, ansible_ctx, get_fixed_version_fn):
    print("\n" + "="*60)
    print("STEP 3+4 -- AI generate + validate Ansible playbooks")
    print("="*60)

    from core.ai_fixer import fix_package_ansible, _top_severity
    from core.ansible_validator import validate_playbook

    MAX_RETRIES  = 2
    os_name      = scan_info.get("os_name", "")
    os_version   = scan_info.get("os_version", "")
    platform     = scan_info.get("platform", "")
    env_type     = scan_info.get("env_type", "unknown")
    system_info  = scan_info.get("system_info") or {}
    hostname     = (scan_info.get("hostname") or
                    scan_info.get("system_info", {}).get("hostname", "unknown"))

    # For docker/k8s environments, target all hosts (no specific container hostname)
    _DYNAMIC_HOST_ENVS = {"docker", "container", "k8s", "kubernetes"}
    if any(k in env_type.lower() for k in _DYNAMIC_HOST_ENVS):
        hosts_pattern = "all"
        print(f"  [INFO] env_type={env_type!r} -> hosts_pattern overridden to 'all'")
    else:
        hosts_pattern = hostname or "all"

    playbook_files = {}
    results = []

    for pkg_name, pkg_findings in packages_map.items():
        display_pkg  = pkg_name if pkg_name != "__unknown__" else ""
        pkg_version  = pkg_findings[0].get("package_version") or "unknown"
        fixed_hint   = get_fixed_version_fn(display_pkg) if display_pkg else None
        cve_ids      = [f.get("cve_id", "") for f in pkg_findings]
        top_sev      = _top_severity(pkg_findings)

        print(f"\n  Package : {display_pkg or 'unknown'}  "
              f"({len(cve_ids)} CVEs, top_sev={top_sev})")
        print(f"  Version : {pkg_version}" +
              (f"  ->  fixed: {fixed_hint}" if fixed_hint else ""))

        yaml_content  = None
        lint_passed   = False
        lint_warnings = []
        error_ctx     = None

        for attempt in range(1 + MAX_RETRIES):
            label = "attempt 1" if attempt == 0 else f"retry {attempt}"
            print(f"  [{label}] Calling Mistral AI ...", end="", flush=True)
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
                print(f" done ({len(yaml_content)} chars)")
            except Exception as e:
                print(f" FAILED: {e}")
                break

            validation = validate_playbook(yaml_content)
            lint_warnings = validation.warnings

            if validation.passed:
                lint_passed = True
                warn_count  = len(validation.warnings)
                lint_status = "PASSED" + (f" ({warn_count} warning(s))" if warn_count else " (clean)")
                print(f"  yamllint  : {lint_status}")
                if validation.lint_available:
                    print(f"  ansiblint : {'PASSED' if not validation.errors else 'see warnings'}")
                else:
                    print(f"  ansiblint : not available on this platform (skipped)")
                break
            else:
                print(f"  yamllint  : {len(validation.errors)} error(s)")
                for err in validation.errors[:3]:
                    print(f"    ERR: {err}")
                error_ctx = validation.as_error_context()
                if attempt == MAX_RETRIES:
                    lint_warnings = validation.errors + validation.warnings
                    print(f"  All retries exhausted -- will push with warnings for human review.")

        pb_filename = f"patch_{display_pkg or 'unknown'}.yml"
        if yaml_content:
            playbook_files[pb_filename] = yaml_content
        else:
            playbook_files[pb_filename] = (
                f"# ERROR: AI generation failed for package '{display_pkg}'\n"
                f"# Manual remediation required.\n"
            )

        results.append({
            "package":          display_pkg or "unknown",
            "playbook_file":    f"vulfix/{SCAN_ID}/{pb_filename}",
            "cves":             cve_ids,
            "highest_severity": top_sev,
            "lint_passed":      lint_passed,
            "lint_warnings":    lint_warnings,
            "yaml":             yaml_content,
        })

    return playbook_files, results


# =============================================================================
# STEP 5 -- Push to GitHub + open PR
# =============================================================================
def step5_push_and_pr(connector, git_token, scan_id, scan_info, playbook_files, results):
    print("\n" + "="*60)
    print("STEP 5 -- Push branch to GitHub + open PR")
    print("="*60)

    from core.git_pusher import GitPusher, build_readme

    os_name      = scan_info.get("os_name", "")
    os_version   = scan_info.get("os_version", "")
    os_label     = f"{os_name} {os_version}".strip()
    hostname     = scan_info.get("hostname") or "unknown"
    env_type     = scan_info.get("env_type", "unknown")
    vul_agent_id = scan_info.get("vul_agent_id")

    pkg_summaries = [
        {
            "package":          r["package"],
            "playbook_file":    r["playbook_file"],
            "cves":             r["cves"],
            "highest_severity": r["highest_severity"],
        }
        for r in results
    ]

    readme = build_readme(
        scan_id=scan_id,
        hostname=hostname,
        os_label=os_label,
        env_type=env_type,
        vul_agent_id=vul_agent_id,
        playbook_summaries=pkg_summaries,
        total_cves=sum(len(r["cves"]) for r in results),
    )

    pusher = GitPusher(
        connector=connector,
        scan_id=scan_id,
        token=git_token,
        repo_url=GIT_REPO_URL,
    )

    cve_list = []
    for r in results:
        cve_list.extend(r["cves"])
    cve_summary = ", ".join(cve_list[:8]) + ("..." if len(cve_list) > 8 else "")

    pr_body = (
        f"## VulFix Automated Remediation\n\n"
        f"**Scan ID**: `{scan_id}`  \n"
        f"**Host**: `{hostname}`  \n"
        f"**OS**: {os_label}  \n"
        f"**Environment**: {env_type}  \n\n"
        f"### CVEs addressed\n"
        f"{cve_summary}\n\n"
        f"### Packages patched\n"
    )
    for r in results:
        status = "[lint OK]" if r["lint_passed"] else "[lint warnings]"
        pr_body += f"- **{r['package']}** ({r['highest_severity']}) {status}\n"

    pr_body += (
        f"\n### How to apply\n"
        f"```bash\n"
        f"# Dry-run first (mandatory)\n"
    )
    for r in results:
        pb = Path(r["playbook_file"]).name
        pr_body += f"ansible-playbook vulfix/{scan_id}/{pb} --check --diff\n"
    pr_body += (
        f"\n# Execute only after review and approval\n"
    )
    for r in results:
        pb = Path(r["playbook_file"]).name
        pr_body += f"ansible-playbook vulfix/{scan_id}/{pb}\n"
    pr_body += "```\n\n> **Note**: No playbook is executed automatically. Human approval required.\n"

    branch_url, pr_url = pusher.push_playbooks(
        playbook_files=playbook_files,
        readme_content=readme,
        pr_title=f"[VulFix] Patch {len(results)} package(s) — {scan_id}",
        pr_body=pr_body,
        create_pr=CREATE_PR,
        base_branch=BASE_BRANCH,
    )

    print(f"\n  [OK] Branch pushed : {branch_url}")
    if pr_url:
        print(f"  [OK] PR opened     : {pr_url}")
    else:
        print(f"  [--] PR not created (CREATE_PR=False or GitHub PR already exists)")

    return branch_url, pr_url


# =============================================================================
# STEP 6 -- Show results
# =============================================================================
def step6_show_results(results, branch_url, pr_url):
    print("\n" + "="*60)
    print("STEP 6 -- Generated playbook content")
    print("="*60)

    for r in results:
        if r.get("yaml"):
            print(f"\n{'='*60}")
            print(f"  FILE: patch_{r['package']}.yml")
            print(f"{'='*60}")
            for i, line in enumerate(r["yaml"].splitlines(), 1):
                print(f"  {i:4d}  {line}")

    print(f"\n{'='*60}")
    print("  LINT SUMMARY")
    print(f"{'='*60}")
    for r in results:
        status = "PASSED " if r["lint_passed"] else "WARNING"
        print(f"  [{status}]  {r['package']:30s}  {r['highest_severity']}")
        for w in r["lint_warnings"][:3]:
            print(f"             {w}")

    print(f"\n{'='*60}")
    print("  TEST COMPLETE")
    print(f"{'='*60}")
    if pr_url:
        print(f"\n  >>> GitHub PR  : {pr_url}")
    print(f"  >>> Branch     : {branch_url}")
    print()
    print("  Next steps:")
    for r in results:
        pb = Path(r["playbook_file"]).name
        print(f"  ansible-playbook vulfix/{SCAN_ID}/{pb} --check --diff")
    print()


# =============================================================================
# MAIN
# =============================================================================
def main():
    git_token = preflight()
    connector = None

    try:
        step0_drop_table()

        scan_info, packages_map, get_fixed_version_fn = step1_load_scan(SCAN_ID)

        hostname = (scan_info.get("hostname") or
                    scan_info.get("system_info", {}).get("hostname", "web-prod-01"))

        connector, ansible_ctx = step2_analyse_repo(git_token, hostname)

        playbook_files, results = step3_generate_playbooks(
            scan_info, packages_map, ansible_ctx, get_fixed_version_fn
        )

        branch_url, pr_url = step5_push_and_pr(
            connector, git_token, SCAN_ID, scan_info, playbook_files, results
        )

        step6_show_results(results, branch_url, pr_url)

    finally:
        if connector:
            connector.cleanup()


if __name__ == "__main__":
    main()
