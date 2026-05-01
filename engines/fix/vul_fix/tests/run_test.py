"""
VulFix End-to-End Test -- local dummy Ansible repo, real DB + real Mistral AI.

Steps:
  0 : Drop legacy vul_remediation table (one-time cleanup)
  1 : Create local dummy Ansible repo (roles/, inventory/, group_vars/, ansible.cfg)
  2 : Load real scan + CVE findings from vulnerability_db (CRITICAL/HIGH, max 2 pkgs)
  3 : Run GitConnector.analyze() against local repo
  4 : Call Mistral AI -- generate Ansible playbook per package
  5 : Validate with yamllint; retry AI on errors (max 2 retries)
  6 : Push to local bare git repo on branch vulfix/{scan_id}
  7 : Print full generated YAML + results summary

Usage:
  cd vul_fix/engine
  python ../tests/run_test.py [scan_id]
  e.g. python ../tests/run_test.py 15032026_017
"""

import os
import sys
import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# -- Add engine to path -------------------------------------------------------
ENGINE_DIR = Path(__file__).parent.parent / "engine"
sys.path.insert(0, str(ENGINE_DIR))

# Load .env from engine dir if present
_env_file = ENGINE_DIR / ".env"
if _env_file.exists():
    from dotenv import load_dotenv
    load_dotenv(_env_file)
    print(f"[Test] Loaded .env from {_env_file}")

# In the test we inject GIT_TOKEN as a dummy value so the router doesn't reject it.
# The actual push uses the local file:// URL which needs no auth.
if not os.environ.get("GIT_TOKEN"):
    os.environ["GIT_TOKEN"] = "dummy-local-token-for-test"

# VUL_FIX_API_KEY must be set for middleware (test bypasses middleware but
# api_server startup validates it — set a dummy for local testing)
if not os.environ.get("VUL_FIX_API_KEY"):
    os.environ["VUL_FIX_API_KEY"] = "test-api-key-local"

# -- Configure logging --------------------------------------------------------
import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("vulfixtest")

# -- Test config --------------------------------------------------------------
SCAN_ID      = sys.argv[1] if len(sys.argv) > 1 else "15032026_017"
MAX_PACKAGES = 2        # limit AI calls to keep test cost low
SEV_FILTER   = ["CRITICAL", "HIGH"]


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
            print("  [SKIP]     vul_remediation table did not exist -- nothing to drop.")
    except Exception as e:
        print(f"  [WARN]     Drop failed (non-fatal): {e}")


# =============================================================================
# STEP 1 -- Build local dummy Ansible repo
# =============================================================================
def step1_create_local_repo():
    """Returns (bare_repo_url, work_dir, bare_dir)."""
    print("\n" + "="*60)
    print("STEP 1 -- Create local dummy Ansible repo")
    print("="*60)

    bare_dir = tempfile.mkdtemp(prefix="vulfix_bare_")
    # Use --initial-branch=main if supported (git >= 2.28), else rename after
    r = subprocess.run(["git", "init", "--bare", "--initial-branch=main", bare_dir],
                       capture_output=True)
    if r.returncode != 0:
        subprocess.run(["git", "init", "--bare", bare_dir], check=True, capture_output=True)

    work_dir = tempfile.mkdtemp(prefix="vulfix_work_")
    subprocess.run(["git", "clone", bare_dir, work_dir], check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "vulfix@test.local"],
                   cwd=work_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "VulFix Test"],
                   cwd=work_dir, check=True, capture_output=True)
    # Ensure we are on a branch called 'main'
    subprocess.run(["git", "checkout", "-b", "main"],
                   cwd=work_dir, capture_output=True)  # ignore error if already on main

    work = Path(work_dir)

    (work / "ansible.cfg").write_text(textwrap.dedent("""\
        [defaults]
        inventory           = inventory/
        remote_user         = ubuntu
        host_key_checking   = False
        retry_files_enabled = False

        [privilege_escalation]
        become        = True
        become_method = sudo
        become_user   = root
    """))

    (work / "requirements.yml").write_text(textwrap.dedent("""\
        ---
        collections:
          - name: ansible.builtin
          - name: community.general
            version: ">=8.0.0"
    """))

    inv_dir = work / "inventory"
    inv_dir.mkdir()
    (inv_dir / "hosts.ini").write_text(textwrap.dedent("""\
        [webservers]
        web-prod-01 ansible_host=10.0.1.10
        web-prod-02 ansible_host=10.0.1.11

        [dbservers]
        db-prod-01 ansible_host=10.0.2.10

        [all:vars]
        ansible_python_interpreter=/usr/bin/python3
    """))

    gv_dir = work / "group_vars"
    gv_dir.mkdir()
    (gv_dir / "all.yml").write_text(textwrap.dedent("""\
        ---
        env_name: production
        org_name: "ACME Corp"
        apt_cache_valid_time: 3600
        maintenance_window: false
    """))
    (gv_dir / "webservers.yml").write_text(textwrap.dedent("""\
        ---
        web_user: www-data
        nginx_port: 443
    """))

    role_tasks = work / "roles" / "common" / "tasks"
    role_tasks.mkdir(parents=True)
    (role_tasks / "main.yml").write_text(textwrap.dedent("""\
        ---
        - name: Update apt cache
          ansible.builtin.apt:
            update_cache: true
            cache_valid_time: "{{ apt_cache_valid_time }}"
          become: true
          tags: [common, apt]

        - name: Ensure base packages are installed
          ansible.builtin.apt:
            name:
              - curl
              - wget
              - ca-certificates
            state: present
          become: true
          tags: [common, packages]

        - name: Patch openssh-server to latest secure version
          ansible.builtin.apt:
            name: "openssh-server"
            state: latest
            update_cache: false
          become: true
          notify: Restart sshd
          tags: [common, security, patch]
    """))

    role_handlers = work / "roles" / "common" / "handlers"
    role_handlers.mkdir(parents=True)
    (role_handlers / "main.yml").write_text(textwrap.dedent("""\
        ---
        - name: Restart sshd
          ansible.builtin.service:
            name: sshd
            state: restarted
          become: true

        - name: Restart nginx
          ansible.builtin.service:
            name: nginx
            state: restarted
          become: true
    """))

    (work / "site.yml").write_text(textwrap.dedent("""\
        ---
        - name: Apply common configuration
          hosts: all
          roles:
            - common
    """))

    subprocess.run(["git", "add", "."], cwd=work_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial Ansible structure"],
                   cwd=work_dir, check=True, capture_output=True)
    # Push to whatever branch we're on, set upstream as 'main'
    subprocess.run(["git", "push", "-u", "origin", "HEAD:main"],
                   cwd=work_dir, check=True, capture_output=True)

    bare_url = f"file://{bare_dir}"
    print(f"  [OK] Bare remote   : {bare_dir}")
    print(f"  [OK] Working clone : {work_dir}")
    print(f"  [OK] Roles         : common")
    print(f"  [OK] Inventory     : inventory/hosts.ini (webservers, dbservers)")
    return bare_url, work_dir, bare_dir


# =============================================================================
# STEP 2 -- Load scan + CVE findings from real DB
# =============================================================================
def step2_load_scan(scan_id):
    print("\n" + "="*60)
    print(f"STEP 2 -- Load scan {scan_id} from vulnerability_db")
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
# STEP 3 -- Analyse local Ansible repo
# =============================================================================
def step3_analyse_repo(bare_url, hostname):
    print("\n" + "="*60)
    print("STEP 3 -- Clone + analyse local Ansible repo")
    print("="*60)

    from core.git_connector import GitConnector
    connector = GitConnector(repo_url=bare_url, token="local-no-auth", base_branch="main")
    ctx = connector.analyze(hostname=hostname)

    print(f"  Structure      : {ctx.structure_type}")
    print(f"  Ansible ver    : {ctx.ansible_version or 'not detected (will use FQCN)'}")
    print(f"  FQCN required  : {ctx.fqcn_required}")
    print(f"  Become method  : {ctx.become_method}")
    print(f"  Remote user    : {ctx.remote_user or '(Ansible default)'}")
    print(f"  Existing roles : {ctx.existing_roles}")
    print(f"  Inventory group: {ctx.inventory_group}")
    print(f"  Has vault      : {ctx.has_vault}")
    print(f"\n  Package task snippet (first 8 lines):")
    for line in ctx.package_task_snippet.splitlines()[:8]:
        print(f"    {line}")

    return connector, ctx


# =============================================================================
# STEP 4+5 -- Generate + validate Ansible playbooks
# =============================================================================
def step4_generate_playbooks(scan_info, packages_map, ansible_ctx, get_fixed_version_fn):
    print("\n" + "="*60)
    print("STEP 4+5 -- AI generate + yamllint validate playbooks")
    print("="*60)

    from core.ai_fixer import fix_package_ansible, _top_severity
    from core.ansible_validator import validate_playbook

    MAX_RETRIES = 2
    os_name     = scan_info.get("os_name", "")
    os_version  = scan_info.get("os_version", "")
    platform    = scan_info.get("platform", "")
    hostname    = (scan_info.get("hostname") or
                   scan_info.get("system_info", {}).get("hostname", "unknown"))
    env_type    = scan_info.get("env_type", "unknown")
    system_info = scan_info.get("system_info") or {}
    hosts_pattern = hostname or "all"

    playbook_files = {}
    results = []

    for pkg_name, pkg_findings in packages_map.items():
        display_pkg = pkg_name if pkg_name != "__unknown__" else ""
        pkg_version = pkg_findings[0].get("package_version") or "unknown"
        fixed_hint  = get_fixed_version_fn(display_pkg) if display_pkg else None
        cve_ids     = [f.get("cve_id", "") for f in pkg_findings]
        top_sev     = _top_severity(pkg_findings)

        print(f"\n  Package : {display_pkg or 'unknown'}  "
              f"({len(cve_ids)} CVEs, top_sev={top_sev})")
        print(f"  Version : {pkg_version}" +
              (f"  ->  fixed: {fixed_hint}" if fixed_hint else ""))

        yaml_content = None
        lint_passed  = False
        lint_warnings= []
        error_ctx    = None

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
                print(f"  yamllint : PASSED" +
                      (f" ({warn_count} warning(s))" if warn_count else " (clean)"))
                break
            else:
                print(f"  yamllint : {len(validation.errors)} error(s)")
                for err in validation.errors[:3]:
                    print(f"    ERR: {err}")
                error_ctx = validation.as_error_context()
                if attempt == MAX_RETRIES:
                    lint_warnings = validation.errors + validation.warnings
                    print(f"  All retries exhausted -- pushing with warnings.")

        pb_filename = f"patch_{display_pkg or 'unknown'}.yml"
        if yaml_content:
            playbook_files[pb_filename] = yaml_content
        else:
            playbook_files[pb_filename] = f"# ERROR: generation failed for {display_pkg}\n"

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
# STEP 6 -- Push to local bare repo
# =============================================================================
def step6_push(connector, bare_url, scan_id, scan_info, playbook_files, results):
    print("\n" + "="*60)
    print("STEP 6 -- Commit + push branch to local bare repo")
    print("="*60)

    from core.git_pusher import GitPusher, build_readme

    os_name      = scan_info.get("os_name", "")
    os_version   = scan_info.get("os_version", "")
    os_label     = f"{os_name} {os_version}".strip()
    hostname     = scan_info.get("hostname") or "unknown"
    env_type     = scan_info.get("env_type", "unknown")
    vul_agent_id = scan_info.get("vul_agent_id")

    pkg_summaries = [
        {"package": r["package"], "playbook_file": r["playbook_file"],
         "cves": r["cves"], "highest_severity": r["highest_severity"]}
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
        token="local-no-auth",
        repo_url=bare_url,
    )
    branch_url, pr_url = pusher.push_playbooks(
        playbook_files=playbook_files,
        readme_content=readme,
        pr_title=f"[VulFix TEST] {scan_id}",
        pr_body="Test run -- local dummy repo.",
        create_pr=False,
        base_branch="main",
    )

    print(f"  [OK] Branch pushed : {branch_url}")
    print(f"  [--] PR skipped    : create_pr=False (local test)")
    return branch_url


# =============================================================================
# STEP 7 -- Show results
# =============================================================================
def step7_show_results(bare_dir, results, branch_url):
    print("\n" + "="*60)
    print("STEP 7 -- Generated Ansible playbooks")
    print("="*60)

    check_dir = tempfile.mkdtemp(prefix="vulfix_check_")
    branch_name = f"vulfix/{SCAN_ID}"
    try:
        subprocess.run(
            ["git", "clone", "--branch", branch_name, "--depth", "1",
             bare_dir, check_dir],
            check=True, capture_output=True,
        )
        playbook_dir = Path(check_dir) / "vulfix" / SCAN_ID
        committed_files = sorted(playbook_dir.iterdir()) if playbook_dir.exists() else []

        print(f"\n  Branch   : {branch_name}")
        print(f"  Files    : {[f.name for f in committed_files]}")

        for f in committed_files:
            print(f"\n{'='*60}")
            print(f"  FILE: {f.name}")
            print(f"{'='*60}")
            for i, line in enumerate(f.read_text(encoding="utf-8",
                                                  errors="replace").splitlines(), 1):
                print(f"  {i:4d}  {line}")
    except Exception as e:
        print(f"  [WARN] Could not read back from bare repo: {e}")
        # Fall back to in-memory results
        for r in results:
            if r.get("yaml"):
                print(f"\n{'='*60}")
                print(f"  PACKAGE: {r['package']}")
                print(f"{'='*60}")
                for i, line in enumerate(r["yaml"].splitlines(), 1):
                    print(f"  {i:4d}  {line}")
    finally:
        shutil.rmtree(check_dir, ignore_errors=True)

    # Summary
    print(f"\n{'='*60}")
    print("  LINT SUMMARY")
    print(f"{'='*60}")
    for r in results:
        status = "PASSED" if r["lint_passed"] else "WARNINGS"
        print(f"  [{status:8s}]  {r['package']:30s}  {r['highest_severity']}")
        for w in r["lint_warnings"][:3]:
            print(f"             {w}")

    print(f"\n{'='*60}")
    print("  TEST COMPLETE")
    print(f"{'='*60}")
    print(f"  Branch: {branch_url}")
    print()
    print("  Next steps (real deployment):")
    print("  1. Use real GitHub repo URL in git_repo_url")
    print("  2. POST /api/v1/vul-fix/remediate with git_token")
    print("  3. Review the PR opened on your GitHub repo")
    print(f"  4. ansible-playbook vulfix/{SCAN_ID}/patch_<pkg>.yml --check --diff")
    print("  5. Execute only after review and approval")


# =============================================================================
# MAIN
# =============================================================================
def main():
    print("\n" + "#"*60)
    print("  VUL-FIX  END-TO-END TEST")
    print("#"*60)
    print(f"  Scan ID     : {SCAN_ID}")
    print(f"  Max packages: {MAX_PACKAGES}")
    print(f"  Sev filter  : {SEV_FILTER}")
    print(f"  Mistral key : {'SET [OK]' if os.getenv('MISTRAL_API_KEY') else 'NOT SET [ERROR]'}")

    if not os.getenv("MISTRAL_API_KEY"):
        raise SystemExit("\n[ERROR] MISTRAL_API_KEY is not set. Add it to .env and re-run.\n")

    bare_url = work_dir = bare_dir = None
    connector = None

    try:
        step0_drop_table()
        bare_url, work_dir, bare_dir = step1_create_local_repo()
        scan_info, packages_map, get_fixed_version_fn = step2_load_scan(SCAN_ID)

        hostname = (scan_info.get("hostname") or
                    scan_info.get("system_info", {}).get("hostname", "web-prod-01"))

        connector, ansible_ctx = step3_analyse_repo(bare_url, hostname)
        playbook_files, results = step4_generate_playbooks(
            scan_info, packages_map, ansible_ctx, get_fixed_version_fn
        )
        branch_url = step6_push(
            connector, bare_url, SCAN_ID, scan_info, playbook_files, results
        )
        step7_show_results(bare_dir, results, branch_url)

    finally:
        if connector:
            connector.cleanup()
        for d in [work_dir, bare_dir]:
            if d and os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
