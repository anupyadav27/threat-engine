"""
GitPusher — commit Ansible playbooks to a new vulfix branch and optionally
open a Pull Request (GitHub) or Merge Request (GitLab).

Branch naming: vulfix/{scan_id}
Files committed:
  vulfix/{scan_id}/README.md         — overview, CVE table, how-to-run
  vulfix/{scan_id}/patch_{pkg}.yml   — one Ansible playbook per package

Security:
  - Git token embedded in remote URL only during push, reset immediately after.
  - Token never logged (masked in all log output).

Idempotency:
  - If the branch already exists on remote, it is deleted and re-created.
    This allows re-running remediation for the same scan_id safely.

PR creation supports GitHub and GitLab (detected by URL pattern).
"""

import logging
import os
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

_MASK = lambda t: f"{'*' * max(len(t) - 4, 0)}{t[-4:]}" if t and len(t) > 4 else "****"


class GitPusher:
    """
    Takes a GitConnector (already cloned) and commits playbook files
    to a new branch, then pushes and optionally creates a PR/MR.
    """

    def __init__(
        self,
        connector,
        scan_id: str,
        token: str,
        repo_url: str,
    ):
        self.connector   = connector
        self.scan_id     = scan_id
        self.token       = token
        self.repo_url    = repo_url.rstrip("/")
        self.branch_name = f"vulfix/{scan_id}"

    def push_playbooks(
        self,
        playbook_files: Dict[str, str],
        readme_content: str,
        pr_title: str,
        pr_body: str,
        create_pr: bool = True,
        base_branch: str = "main",
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Create branch, commit all playbooks + README, push, optionally create PR.
        Returns (branch_url, pr_url). Either may be None on partial failure.
        Idempotent: deletes and recreates the branch if it already exists.
        """
        repo = self.connector.repo
        if repo is None:
            raise RuntimeError("GitConnector has no repo — call clone() first.")

        repo_root = Path(self.connector.repo_path)
        subdir    = repo_root / "vulfix" / self.scan_id
        subdir.mkdir(parents=True, exist_ok=True)

        # ── 1. Idempotent branch creation ─────────────────────────────────────
        # Delete existing local branch if present, then create fresh
        if self.branch_name in [h.name for h in repo.heads]:
            logger.info(
                f"[GitPusher] Branch '{self.branch_name}' already exists locally — deleting for re-run"
            )
            repo.delete_head(self.branch_name, force=True)

        new_branch = repo.create_head(self.branch_name)
        new_branch.checkout()
        logger.info(f"[GitPusher] Branch '{self.branch_name}' created and checked out")

        # ── 2. Write files ────────────────────────────────────────────────────
        written_paths = []

        readme_path = subdir / "README.md"
        readme_path.write_text(readme_content, encoding="utf-8")
        written_paths.append(str(readme_path.relative_to(repo_root)))

        for filename, yaml_content in playbook_files.items():
            # Sanitise filename — strip any path separators (defence in depth)
            safe_name = Path(filename).name
            if safe_name != filename:
                logger.warning(f"[GitPusher] Filename sanitised: '{filename}' -> '{safe_name}'")
            pb_path = subdir / safe_name
            pb_path.write_text(yaml_content, encoding="utf-8")
            written_paths.append(str(pb_path.relative_to(repo_root)))

        logger.info(f"[GitPusher] Written {len(written_paths)} file(s) to {subdir}")

        # ── 3. Stage and commit ───────────────────────────────────────────────
        # Use forward slashes for git index (works cross-platform)
        index_paths = [p.replace("\\", "/") for p in written_paths]
        repo.index.add(index_paths)

        commit_msg = (
            f"vulfix({self.scan_id}): AI-generated security patch playbooks\n\n"
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"Packages : {', '.join(Path(f).stem.replace('patch_', '') for f in playbook_files)}\n\n"
            f"REVIEW REQUIRED before running any playbook.\n"
            f"Dry-run: ansible-playbook <playbook> --check --diff"
        )
        repo.index.commit(commit_msg)
        logger.info(f"[GitPusher] Committed {len(written_paths)} file(s)")

        # ── 4. Push (with auth URL, reset after) ─────────────────────────────
        auth_url = self._build_auth_url()
        origin   = repo.remote("origin")
        try:
            origin.set_url(auth_url)
            # Force-push to overwrite remote branch if it exists from a previous run
            push_info_list = origin.push(
                refspec=f"{self.branch_name}:{self.branch_name}",
                force=True,
            )
            for pi in push_info_list:
                if pi.flags & pi.ERROR:
                    raise RuntimeError(f"Push rejected: {pi.summary}")
            logger.info(f"[GitPusher] Branch '{self.branch_name}' pushed (token=...{_MASK(self.token)})")
        finally:
            # Always restore to token-free URL regardless of outcome
            try:
                origin.set_url(self.repo_url)
            except Exception:
                pass

        branch_url = self._build_branch_url()

        # ── 5. Create PR / MR ─────────────────────────────────────────────────
        pr_url = None
        if create_pr:
            try:
                if "gitlab" in self.repo_url.lower():
                    pr_url = self._create_gitlab_mr(pr_title, pr_body, base_branch)
                else:
                    pr_url = self._create_github_pr(pr_title, pr_body, base_branch)
            except Exception as e:
                logger.warning(
                    f"[GitPusher] PR creation failed (branch pushed OK, create PR manually): {e}"
                )

        logger.info(f"[GitPusher] Done. branch={self.branch_name}  pr={pr_url or 'N/A'}")
        return branch_url, pr_url

    # ── URL helpers ───────────────────────────────────────────────────────────

    def _build_auth_url(self) -> str:
        if self.repo_url.startswith("file://") or self.repo_url.startswith("/"):
            return self.repo_url
        return re.sub(r"^https://", f"https://x-token:{self.token}@", self.repo_url)

    def _build_branch_url(self) -> Optional[str]:
        if self.repo_url.startswith("file://") or self.repo_url.startswith("/"):
            return f"{self.repo_url} (branch: {self.branch_name})"
        url = self.repo_url.rstrip(".git")
        if "github.com" in url:
            return f"{url}/tree/{self.branch_name}"
        if "gitlab" in url:
            return f"{url}/-/tree/{self.branch_name}"
        return None

    # ── GitHub PR ─────────────────────────────────────────────────────────────

    def _parse_github_owner_repo(self) -> Tuple[str, str]:
        m = re.search(r"github\.com[:/](.+?)/(.+?)(?:\.git)?$", self.repo_url)
        if not m:
            raise ValueError(f"Cannot parse GitHub owner/repo from: {self.repo_url}")
        return m.group(1), m.group(2)

    def _create_github_pr(self, title: str, body: str, base_branch: str) -> Optional[str]:
        owner, repo_name = self._parse_github_owner_repo()
        api_url = f"https://api.github.com/repos/{owner}/{repo_name}/pulls"

        # Check if PR already exists for this branch
        existing = requests.get(
            api_url,
            headers={
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            params={"head": f"{owner}:{self.branch_name}", "state": "open"},
            timeout=30,
        )
        if existing.ok and existing.json():
            existing_url = existing.json()[0].get("html_url")
            logger.info(f"[GitPusher] PR already exists: {existing_url}")
            return existing_url

        resp = requests.post(
            api_url,
            headers={
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={
                "title": title,
                "body":  body,
                "head":  self.branch_name,
                "base":  base_branch,
            },
            timeout=30,
        )
        resp.raise_for_status()
        pr_url = resp.json().get("html_url")
        logger.info(f"[GitPusher] GitHub PR created: {pr_url}")
        return pr_url

    # ── GitLab MR ─────────────────────────────────────────────────────────────

    def _create_gitlab_mr(self, title: str, body: str, base_branch: str) -> Optional[str]:
        m = re.search(r"gitlab[^/]*/(.+?)(?:\.git)?$", self.repo_url)
        if not m:
            raise ValueError(f"Cannot parse GitLab project path from: {self.repo_url}")
        project_path = m.group(1)

        host_m      = re.search(r"(https?://[^/]+)", self.repo_url)
        gitlab_host = host_m.group(1) if host_m else "https://gitlab.com"

        import urllib.parse
        encoded_path = urllib.parse.quote(project_path, safe="")
        api_url      = f"{gitlab_host}/api/v4/projects/{encoded_path}/merge_requests"

        resp = requests.post(
            api_url,
            headers={
                "PRIVATE-TOKEN": self.token,
                "Content-Type":  "application/json",
            },
            json={
                "title":                title,
                "description":          body,
                "source_branch":        self.branch_name,
                "target_branch":        base_branch,
                "remove_source_branch": False,
            },
            timeout=30,
        )
        resp.raise_for_status()
        mr_url = resp.json().get("web_url")
        logger.info(f"[GitPusher] GitLab MR created: {mr_url}")
        return mr_url


# ── README builder ────────────────────────────────────────────────────────────

def build_readme(
    scan_id: str,
    hostname: str,
    os_label: str,
    env_type: str,
    vul_agent_id: Optional[str],
    playbook_summaries: List[dict],
    inventory_pattern: str = "all",
    total_cves: int = 0,
    severity_counts: Optional[dict] = None,
) -> str:
    sc       = severity_counts or {}
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev_line = "  |  ".join(
        f"{s}: {sc.get(s, 0)}"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if sc.get(s, 0)
    )

    pkg_rows = "\n".join(
        f"| `{p['package']}` | {p['highest_severity']} "
        f"| {', '.join(p['cves'][:3])}{'...' if len(p['cves']) > 3 else ''} "
        f"| `{p['playbook_file']}` |"
        for p in playbook_summaries
    )

    dry_run_cmds = "\n".join(
        f"ansible-playbook -i inventory/ {p['playbook_file']} --check --diff"
        for p in playbook_summaries
    )
    run_cmds = "\n".join(
        f"ansible-playbook -i inventory/ {p['playbook_file']}"
        for p in playbook_summaries
    )

    return textwrap.dedent(f"""\
    # VulFix — Security Patch Playbooks

    > **IMPORTANT: Do NOT run these playbooks without review.**
    > 1. Review each `.yml` file in this branch carefully.
    > 2. Run in `--check` (dry-run) mode first and review the diff.
    > 3. Execute only during an approved maintenance window.
    > 4. Merge this PR **after** confirming the patch was applied successfully.

    ---

    ## Scan Details

    | Field           | Value |
    |-----------------|-------|
    | **Scan ID**     | `{scan_id}` |
    | **Generated**   | {date_str} |
    | **Hostname**    | `{hostname}` |
    | **OS**          | {os_label} |
    | **Environment** | {env_type} |
    | **User Agent**  | `{vul_agent_id or 'N/A'}` |
    | **Total CVEs**  | {total_cves} |
    | **Severity**    | {sev_line or 'N/A'} |

    ---

    ## Packages to Patch

    | Package | Severity | CVEs (sample) | Playbook |
    |---------|----------|---------------|----------|
    {pkg_rows}

    ---

    ## How to Run

    ### Step 1 — Dry Run (MANDATORY — review output before proceeding)
    ```bash
    {dry_run_cmds}
    ```

    ### Step 2 — Execute after review and change-control approval
    ```bash
    {run_cmds}
    ```

    ### Step 3 — Verify
    After running, verify that:
    - Package versions are at the patched versions shown in each playbook
    - All dependent services are running (`systemctl status <service>`)
    - The `ansible.builtin.assert` task reported SUCCESS in the play output

    ---

    ## Safety Reminders

    - **Change control**: Obtain approval before patching production systems.
    - **Docker/containers**: Runtime patches are not persistent. Rebuild the image
      using the `Dockerfile RUN` lines shown in each playbook.
    - **Kubernetes**: Update the Deployment image tag after patching the base image,
      then run `kubectl rollout restart`.
    - **Idempotency**: These playbooks are safe to re-run — they will skip if already patched.
    - **Rollback**: Pin to the previous version in the apt task if a rollback is needed.

    ---
    *Auto-generated by VulFix Engine v2. Human review and approval required before execution.*
    """)
