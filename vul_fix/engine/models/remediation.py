"""
Request / Response models for vul_fix Ansible+Git remediation API.

Security notes:
  - git_token is intentionally EXCLUDED from the request body.
    It must be provided via the GIT_TOKEN environment variable (K8s secret).
    Accepting tokens over HTTP risks leaking them in access logs, reverse proxy
    logs, and API gateway logs. Use env var only.
  - scan_id is validated against a strict allowlist regex to prevent
    path traversal attacks in git branch names.
"""

import re
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


# Strict scan_id pattern — only alphanumeric, underscore, hyphen; max 100 chars
_SCAN_ID_RE = re.compile(r'^[a-zA-Z0-9_-]{1,100}$')


# ── Request ────────────────────────────────────────────────────────────────────

class VulFixRequest(BaseModel):
    scan_id: str = Field(
        ...,
        description=(
            "Vulnerability scan ID from vul_engine (e.g., '05042025_001'). "
            "Only alphanumeric characters, hyphens, and underscores are accepted."
        )
    )
    git_repo_url: str = Field(
        ...,
        description=(
            "HTTPS URL of the organisation's Ansible Git repository "
            "(e.g., 'https://github.com/org/ansible-infra'). "
            "SSH URLs are not supported."
        )
    )
    git_base_branch: str = Field(
        "main",
        description="Base branch to create the vulfix branch from. Default: main."
    )
    severity_filter: Optional[List[str]] = Field(
        None,
        description=(
            "Only generate playbooks for these severities. "
            "e.g. ['CRITICAL','HIGH']. None = all severities."
        )
    )
    create_pr: bool = Field(
        True,
        description=(
            "Open a Pull Request / Merge Request after pushing the branch. "
            "Requires a token with PR creation permissions."
        )
    )
    target_hosts_override: Optional[str] = Field(
        None,
        description=(
            "Override the Ansible hosts pattern used in generated playbooks. "
            "If not set, the engine uses the hostname from the scan. "
            "For Docker/container scans the engine automatically defaults to 'all' "
            "since container IDs are not valid Ansible inventory hostnames. "
            "Example values: 'webservers', 'prod:&patching', 'all'."
        )
    )

    @field_validator("scan_id")
    @classmethod
    def validate_scan_id(cls, v: str) -> str:
        if not _SCAN_ID_RE.match(v):
            raise ValueError(
                f"scan_id '{v}' contains invalid characters. "
                "Only alphanumeric characters, hyphens, and underscores are allowed "
                "(max 100 characters). This prevents path traversal in git branch names."
            )
        return v

    @field_validator("git_repo_url")
    @classmethod
    def validate_git_repo_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://") and not v.startswith("file://"):
            raise ValueError(
                "git_repo_url must use HTTPS (e.g. https://github.com/org/repo). "
                "SSH URLs are not supported — use HTTPS with a PAT token."
            )
        # SSRF guard — block private IPs and cloud metadata endpoints
        if v.startswith("https://"):
            from core.ssrf_guard import validate_git_url
            validate_git_url(v)
        return v

    @field_validator("severity_filter")
    @classmethod
    def validate_severity_filter(cls, v):
        if v is None:
            return v
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        upper   = [s.upper() for s in v]
        invalid = set(upper) - allowed
        if invalid:
            raise ValueError(
                f"Invalid severity values: {invalid}. "
                f"Allowed: {allowed}"
            )
        return upper

    @field_validator("target_hosts_override")
    @classmethod
    def validate_hosts_override(cls, v):
        if v is None:
            return v
        # Prevent shell injection via hosts pattern
        if re.search(r'[;|&`$()<>]', v):
            raise ValueError(
                "target_hosts_override contains invalid characters. "
                "Use plain Ansible host patterns (e.g. 'webservers', 'all', 'prod:&patching')."
            )
        return v.strip()


# ── Playbook-level result ──────────────────────────────────────────────────────

class PlaybookResult(BaseModel):
    package_name: str
    playbook_file: str                   # e.g. "vulfix/02042026_001/patch_curl.yml"
    cve_ids: List[str]
    highest_severity: str
    highest_cvss: Optional[float]
    lint_passed: bool
    lint_warnings: List[str] = []
    error: Optional[str] = None          # set only when generation completely failed


# ── Response ───────────────────────────────────────────────────────────────────

class VulFixResponse(BaseModel):
    scan_id: str
    agent_id: Optional[str]
    vul_agent_id: Optional[str]
    hostname: str
    os_label: str
    env_type: str
    ansible_hosts_pattern: str

    git_repo_url: str
    git_branch: str
    git_branch_url: Optional[str]
    pr_url: Optional[str]

    packages_processed: int
    total_cves: int
    severity_counts: dict

    playbooks: List[PlaybookResult]
    how_to_run: List[str] = []
    message: str
