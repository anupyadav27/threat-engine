"""
GitConnector — shallow-clone the organisation's Ansible Git repository and
extract structured context so Mistral AI can generate playbooks that match
the org's existing conventions.

What it extracts
----------------
  structure_type      : "role-based" | "flat" | "collections" | "unknown"
  ansible_version     : detected from requirements.yml / setup.cfg / galaxy.yml
  become_method       : from ansible.cfg  (default: sudo)
  remote_user         : from ansible.cfg  (default: None → Ansible default)
  package_task_snippet: existing apt/yum/dnf/package task examples (≤60 lines)
  group_vars_snippet  : group_vars relevant to target host (≤40 lines)
  inventory_group     : Ansible group the target host belongs to
  existing_roles      : list of role names under roles/
  has_vault           : whether vault-encrypted files are present

Security note
-------------
  The HTTPS clone URL is built as:
    https://x-token:<token>@github.com/org/repo.git
  The token is never logged. The temp directory is always deleted in cleanup().
"""

import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Max lines to include from any single file in the AI context
_MAX_SNIPPET_LINES = 60
# Max files to scan when hunting for package task examples
_MAX_FILES_TO_SCAN = 200


@dataclass
class AnsibleRepoContext:
    """All Ansible-repo intelligence that gets sent to the AI prompt."""
    structure_type: str = "unknown"         # role-based / flat / collections / unknown
    ansible_version: Optional[str] = None  # e.g. "2.16" or "8.x"
    become_method: str = "sudo"
    remote_user: Optional[str] = None
    fqcn_required: bool = True             # True when ansible_version >= 2.10

    # Snippets sent verbatim to AI — trimmed for context window
    package_task_snippet: str = ""         # existing apt/yum/package task example
    group_vars_snippet: str = ""           # group_vars for target host group
    inventory_group: str = "all"           # best-guess group for target host
    inventory_entry: str = ""              # raw inventory line for target host

    existing_roles: list = field(default_factory=list)
    has_vault: bool = False
    has_requirements_yml: bool = False

    # Raw summary for AI prompt header
    summary: str = ""


class GitConnector:
    """
    Clone, analyse, and clean up an Ansible Git repository.

    Usage:
        gc = GitConnector(repo_url, token, base_branch="main")
        context = gc.analyze(hostname="web-prod-01")
        gc.cleanup()    # always call — removes temp dir

    The temp clone is reused for git_pusher to create the new branch,
    so call cleanup() only after GitPusher is done.
    """

    def __init__(self, repo_url: str, token: str, base_branch: str = "main"):
        self.repo_url = repo_url.rstrip("/")
        self.token = token
        self.base_branch = base_branch
        self._tmpdir: Optional[str] = None
        self._repo_path: Optional[Path] = None
        self._git_repo = None  # git.Repo object, set after clone

    # ── Public API ────────────────────────────────────────────────────────────

    def clone(self) -> Path:
        """
        Shallow-clone the repo (depth=1) to a temp directory.
        Returns the Path to the cloned repo root.
        Raises RuntimeError on auth/network failure.
        """
        try:
            from git import Repo, GitCommandError  # noqa: import inside method
        except ImportError:
            raise RuntimeError(
                "gitpython is not installed. Add 'gitpython' to requirements.txt."
            )

        self._tmpdir = tempfile.mkdtemp(prefix="vulfix_repo_")
        auth_url = self._build_auth_url()

        logger.info(f"[Git] Cloning {self.repo_url} (branch={self.base_branch}, depth=1) …")
        try:
            self._git_repo = Repo.clone_from(
                auth_url,
                self._tmpdir,
                branch=self.base_branch,
                depth=1,
                single_branch=True,
            )
            self._repo_path = Path(self._tmpdir)
            logger.info(f"[Git] Clone complete → {self._tmpdir}")
            return self._repo_path
        except Exception as e:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None
            raise RuntimeError(f"Git clone failed: {e}") from e

    def analyze(self, hostname: str = "") -> AnsibleRepoContext:
        """
        Clone (if not already done) then analyse the repo.
        Returns an AnsibleRepoContext ready to embed in the AI prompt.
        """
        if self._repo_path is None:
            self.clone()

        ctx = AnsibleRepoContext()
        root = self._repo_path

        self._detect_structure(root, ctx)
        self._detect_ansible_version(root, ctx)
        self._parse_ansible_cfg(root, ctx)
        self._find_package_task_snippets(root, ctx)
        self._find_inventory_group(root, hostname, ctx)
        self._find_group_vars(root, ctx)
        self._detect_vault(root, ctx)

        ctx.summary = self._build_summary(ctx)
        logger.info(f"[Git] Repo analysis complete: {ctx.structure_type}, "
                    f"ansible={ctx.ansible_version}, host_group={ctx.inventory_group}")
        return ctx

    def cleanup(self):
        """Remove the temp clone directory. Always call this when done."""
        if self._tmpdir and os.path.exists(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            logger.info(f"[Git] Temp clone removed: {self._tmpdir}")
            self._tmpdir = None
            self._repo_path = None

    @property
    def repo(self):
        """Return the underlying git.Repo object (needed by GitPusher)."""
        return self._git_repo

    @property
    def repo_path(self) -> Optional[Path]:
        return self._repo_path

    # ── Private helpers ───────────────────────────────────────────────────────

    def _build_auth_url(self) -> str:
        """Embed token into HTTPS URL. Never logged. Local file:// URLs are returned as-is."""
        if self.repo_url.startswith("file://") or self.repo_url.startswith("/"):
            return self.repo_url  # local repos don't need auth
        return re.sub(r"^https://", f"https://x-token:{self.token}@", self.repo_url)

    def _detect_structure(self, root: Path, ctx: AnsibleRepoContext):
        """Determine if this is a role-based, flat, or collections repo."""
        if (root / "roles").is_dir() and any((root / "roles").iterdir()):
            ctx.structure_type = "role-based"
            ctx.existing_roles = [
                d.name for d in (root / "roles").iterdir()
                if d.is_dir() and not d.name.startswith(".")
            ]
        elif (root / "collections").is_dir() or (root / "galaxy.yml").exists():
            ctx.structure_type = "collections"
        elif any(root.glob("*.yml")) or any(root.glob("playbooks/*.yml")):
            ctx.structure_type = "flat"
        else:
            ctx.structure_type = "unknown"
        ctx.has_requirements_yml = (root / "requirements.yml").exists()

    def _detect_ansible_version(self, root: Path, ctx: AnsibleRepoContext):
        """Parse ansible version from requirements.yml, setup.cfg, or galaxy.yml."""
        # requirements.yml
        for req_file in [root / "requirements.yml", root / "requirements.yaml"]:
            if req_file.exists():
                text = req_file.read_text(errors="ignore")
                m = re.search(r"ansible[_-]core[^:]*:\s*[>=<]*\s*([0-9]+\.[0-9]+)", text, re.I)
                if m:
                    ctx.ansible_version = m.group(1)
                    break
                m = re.search(r"ansible\s*[>=<]+\s*([0-9]+\.[0-9]+)", text, re.I)
                if m:
                    ctx.ansible_version = m.group(1)
                    break
        # galaxy.yml
        if not ctx.ansible_version:
            galaxy = root / "galaxy.yml"
            if galaxy.exists():
                m = re.search(r"version:\s*([0-9]+\.[0-9]+)", galaxy.read_text(errors="ignore"))
                if m:
                    ctx.ansible_version = m.group(1)

        # Decide FQCN: required for ansible >= 2.10 (released 2020)
        if ctx.ansible_version:
            try:
                major = int(ctx.ansible_version.split(".")[0])
                minor = int(ctx.ansible_version.split(".")[1])
                ctx.fqcn_required = (major > 2) or (major == 2 and minor >= 10)
            except Exception:
                ctx.fqcn_required = True
        else:
            ctx.fqcn_required = True  # assume modern

    def _parse_ansible_cfg(self, root: Path, ctx: AnsibleRepoContext):
        """Extract become_method and remote_user from ansible.cfg."""
        cfg_file = root / "ansible.cfg"
        if not cfg_file.exists():
            return
        try:
            import configparser
            cfg = configparser.ConfigParser()
            cfg.read(str(cfg_file))
            defaults = cfg.defaults()
            ctx.become_method = defaults.get("become_method", "sudo")
            ctx.remote_user   = defaults.get("remote_user", None)
        except Exception as e:
            logger.debug(f"[Git] ansible.cfg parse error: {e}")

    def _find_package_task_snippets(self, root: Path, ctx: AnsibleRepoContext):
        """
        Hunt through .yml files for existing apt/yum/dnf/package module tasks.
        Returns the first clean snippet found (≤60 lines).
        """
        package_patterns = [
            r"ansible\.builtin\.(apt|yum|dnf|package|zypper|apk|pacman)",
            r"^\s+(apt|yum|dnf|package|zypper|apk):\s*$",
            r"^\s+(apt|yum|dnf|package|zypper|apk):\s*\n",
        ]
        combined = re.compile("|".join(package_patterns), re.MULTILINE)

        candidates = []
        # Search roles/*/tasks/ first, then playbooks/, then root
        search_dirs = []
        for role_tasks in root.glob("roles/*/tasks"):
            search_dirs.append(role_tasks)
        for pb_dir in [root / "playbooks", root / "tasks", root]:
            if pb_dir.is_dir():
                search_dirs.append(pb_dir)

        files_checked = 0
        for search_dir in search_dirs:
            for yml_file in search_dir.glob("*.yml"):
                if files_checked >= _MAX_FILES_TO_SCAN:
                    break
                files_checked += 1
                try:
                    text = yml_file.read_text(errors="ignore")
                    if combined.search(text):
                        candidates.append((yml_file, text))
                except Exception:
                    continue
            if candidates:
                break

        if not candidates:
            ctx.package_task_snippet = "# No existing package task found in this repo."
            return

        # Pick the shortest file (most focused)
        candidates.sort(key=lambda x: len(x[1]))
        chosen_file, chosen_text = candidates[0]
        lines = chosen_text.splitlines()
        snippet_lines = lines[:_MAX_SNIPPET_LINES]
        if len(lines) > _MAX_SNIPPET_LINES:
            snippet_lines.append(f"# … ({len(lines) - _MAX_SNIPPET_LINES} more lines truncated)")
        ctx.package_task_snippet = (
            f"# Source: {chosen_file.relative_to(root)}\n"
            + "\n".join(snippet_lines)
        )

    def _find_inventory_group(self, root: Path, hostname: str, ctx: AnsibleRepoContext):
        """Search inventory files for the hostname and extract its group."""
        if not hostname:
            ctx.inventory_group = "all"
            return

        # Common inventory locations
        inv_dirs = []
        for inv_candidate in ["inventory", "inventories", "hosts"]:
            p = root / inv_candidate
            if p.is_dir():
                inv_dirs.append(p)
        # Also check root-level inventory files
        for f in root.glob("inventory*"):
            if f.is_file():
                inv_dirs.append(f.parent)
                break

        for inv_dir in inv_dirs:
            for inv_file in list(inv_dir.rglob("*.ini")) + list(inv_dir.rglob("*.yml")) + \
                            list(inv_dir.rglob("*.yaml")) + list(inv_dir.rglob("hosts")):
                try:
                    text = inv_file.read_text(errors="ignore")
                    if hostname not in text:
                        continue
                    # INI format: find group header above the hostname line
                    lines = text.splitlines()
                    current_group = "all"
                    for line in lines:
                        stripped = line.strip()
                        group_m = re.match(r"^\[([^\]:]+)\]", stripped)
                        if group_m:
                            g = group_m.group(1)
                            if not g.endswith(":children") and not g.endswith(":vars"):
                                current_group = g
                        elif hostname in stripped:
                            ctx.inventory_group = current_group
                            ctx.inventory_entry = stripped
                            return
                except Exception:
                    continue

        ctx.inventory_group = "all"

    def _find_group_vars(self, root: Path, ctx: AnsibleRepoContext):
        """Load group_vars for the detected inventory group."""
        if not ctx.inventory_group or ctx.inventory_group == "all":
            return

        group_vars_path = root / "group_vars" / ctx.inventory_group
        if not group_vars_path.exists():
            # Try group_vars/all
            group_vars_path = root / "group_vars" / "all"
        if not group_vars_path.exists():
            return

        snippets = []
        target = (
            list(group_vars_path.glob("*.yml"))
            if group_vars_path.is_dir()
            else [group_vars_path]
        )
        for gv_file in target[:2]:  # max 2 files
            try:
                lines = gv_file.read_text(errors="ignore").splitlines()
                snippets.append(
                    f"# {gv_file.relative_to(root)}\n"
                    + "\n".join(lines[:40])
                )
            except Exception:
                continue
        ctx.group_vars_snippet = "\n\n".join(snippets)

    def _detect_vault(self, root: Path, ctx: AnsibleRepoContext):
        ctx.has_vault = any(root.rglob("*.vault")) or any(root.rglob("vault.yml")) or \
                        any(root.rglob("secrets.yml"))

    def _build_summary(self, ctx: AnsibleRepoContext) -> str:
        roles_str = ", ".join(ctx.existing_roles[:10]) or "none"
        return (
            f"Structure: {ctx.structure_type} | "
            f"Ansible: {ctx.ansible_version or 'unknown'} | "
            f"Become: {ctx.become_method} | "
            f"FQCN: {'yes' if ctx.fqcn_required else 'no'} | "
            f"Vault: {'yes' if ctx.has_vault else 'no'} | "
            f"Roles: [{roles_str}]"
        )
