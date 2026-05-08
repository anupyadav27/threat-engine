"""
Git repository credential validator.

Verifies that the supplied PAT or SSH key grants read access to the repository
by running ``git ls-remote <url> HEAD`` with a 10-second timeout.

Security controls implemented here:
- PAT is never embedded in a URL or logged; it is passed via a GIT_ASKPASS helper
  script that Git executes in-process (same pattern as SECOPS-02 B-1).
- GIT_ASKPASS helper and SSH key temp file are always deleted in a ``finally`` block.
- PAT patterns (``ghp_*``, ``glpat-*``, ``BBDC-*``) are redacted from subprocess
  stderr before any log call.
- ``repo_url`` is validated against an ALLOWED_HOSTS allowlist to block SSRF.
- Subprocess timeout is enforced at 10 seconds; the process is killed on expiry.
"""
import logging
import os
import re
import stat
import subprocess
import tempfile
from typing import Any, Dict
from urllib.parse import urlparse

from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult

logger = logging.getLogger(__name__)

# Timeout in seconds for git ls-remote
_GIT_TIMEOUT_SECONDS = 10


class GitValidator(BaseValidator):
    """Validates git repository credentials by attempting git ls-remote HEAD.

    Supports ``pat_token`` and ``ssh_key`` credential types.
    The repo_url must resolve to one of the ALLOWED_HOSTS; any other host is
    rejected to prevent SSRF via the git subprocess.
    """

    ALLOWED_HOSTS: frozenset = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

    PAT_REDACT_PATTERN: re.Pattern = re.compile(
        r"(ghp_[A-Za-z0-9]+|glpat-[A-Za-z0-9_-]+|BBDC-[A-Za-z0-9]+)"
    )

    # ── Public interface ──────────────────────────────────────────────────────

    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Validate git credentials by running git ls-remote HEAD.

        The method is declared async to conform to ``BaseValidator.validate``
        but the subprocess call is synchronous (fast, 10-second cap).

        Args:
            credentials: Dict that must contain at minimum:
                ``credential_type`` – ``"pat_token"`` or ``"ssh_key"``
                ``repo_url``        – HTTPS or SSH git URL
                For PAT:  ``pat_token`` – personal access token string
                For SSH:  ``private_key`` – PEM-encoded private key string

        Returns:
            ValidationResult with ``success=True`` and ``account_number``
            set to ``"{org}/{repo}"`` on success, or ``success=False`` with
            a sanitized error message on failure.
        """
        # Support nested credentials wrapper written by Secrets Manager
        creds = credentials.get("credentials", credentials)
        credential_type = creds.get("credential_type", credentials.get("credential_type", ""))
        repo_url = creds.get("repo_url") or credentials.get("repo_url", "")

        if not repo_url:
            return self._create_error_result(
                "repo_url is required",
                errors=["Provide 'repo_url' in credentials"],
            )

        # SSRF guard — only allow known public VCS hosts
        ssrf_error = self._check_allowed_host(repo_url)
        if ssrf_error:
            return self._create_error_result(ssrf_error, errors=[ssrf_error])

        safe_url = self._sanitize_url(repo_url)

        if credential_type == "pat_token":
            pat = creds.get("pat_token") or credentials.get("pat_token", "")
            if not pat:
                return self._create_error_result(
                    "pat_token is required for credential_type='pat_token'",
                    errors=["Missing pat_token"],
                )
            return self._validate_with_pat(repo_url, pat, safe_url)

        if credential_type == "ssh_key":
            private_key = creds.get("private_key") or credentials.get("private_key", "")
            if not private_key:
                return self._create_error_result(
                    "private_key is required for credential_type='ssh_key'",
                    errors=["Missing private_key"],
                )
            return self._validate_with_ssh(repo_url, private_key, safe_url)

        return self._create_error_result(
            f"Unsupported credential_type: '{credential_type}'",
            errors=["Supported types: pat_token, ssh_key"],
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _check_allowed_host(self, repo_url: str) -> str:
        """Return an error string if the host is not in ALLOWED_HOSTS, else ''."""
        try:
            parsed = urlparse(repo_url)
            host = parsed.hostname or ""
            # Strip 'www.' prefix for robustness
            host = host.lower().lstrip("www.")
            if host not in self.ALLOWED_HOSTS:
                return (
                    f"repo_url host '{host}' is not in the allowed VCS hosts: "
                    + ", ".join(sorted(self.ALLOWED_HOSTS))
                )
        except Exception:
            return "repo_url could not be parsed"
        return ""

    @staticmethod
    def _sanitize_url(repo_url: str) -> str:
        """Return the URL with any embedded credentials stripped (safe to log)."""
        try:
            parsed = urlparse(repo_url)
            # Rebuild without username/password
            safe = parsed._replace(netloc=parsed.hostname or "")
            if parsed.port:
                safe = safe._replace(netloc=f"{parsed.hostname}:{parsed.port}")
            return safe.geturl()
        except Exception:
            return "<unparseable-url>"

    @staticmethod
    def _extract_account_number(repo_url: str) -> str:
        """Extract '{org}/{repo}' from the URL path.

        Examples:
            https://github.com/myorg/myrepo.git  →  myorg/myrepo
            git@github.com:myorg/myrepo.git      →  myorg/myrepo
        """
        # Handle SSH URLs: git@github.com:org/repo.git
        if repo_url.startswith("git@"):
            path_part = repo_url.split(":", 1)[-1]
        else:
            path_part = urlparse(repo_url).path.lstrip("/")

        # Strip trailing .git
        path_part = path_part.removesuffix(".git").strip("/")

        # Take last two path components as org/repo
        parts = path_part.split("/")
        if len(parts) >= 2:
            return f"{parts[-2]}/{parts[-1]}"
        return path_part or "unknown/unknown"

    def _redact_stderr(self, raw: str) -> str:
        """Replace PAT patterns in stderr before logging."""
        return self.PAT_REDACT_PATTERN.sub("***", raw)

    def _validate_with_pat(
        self, repo_url: str, pat: str, safe_url: str
    ) -> ValidationResult:
        """Run git ls-remote using a GIT_ASKPASS helper so the PAT never appears
        in command-line arguments or log lines.

        The helper script is created at mode 0700, used once, then deleted.
        """
        askpass_fd, askpass_path = tempfile.mkstemp(prefix="git_askpass_", suffix=".sh")
        try:
            # Write the helper that echoes the PAT to Git's password prompt
            helper_content = f"#!/bin/sh\necho '{pat}'\n"
            with os.fdopen(askpass_fd, "w") as fh:
                fh.write(helper_content)
            os.chmod(askpass_path, stat.S_IRWXU)  # 0700

            env = {**os.environ, "GIT_ASKPASS": askpass_path, "GIT_TERMINAL_PROMPT": "0"}
            return self._run_ls_remote(repo_url, env, safe_url)
        finally:
            if os.path.exists(askpass_path):
                os.unlink(askpass_path)

    def _validate_with_ssh(
        self, repo_url: str, private_key: str, safe_url: str
    ) -> ValidationResult:
        """Run git ls-remote using an SSH key written to a temp file (mode 0600)."""
        key_fd, key_path = tempfile.mkstemp(prefix="git_ssh_key_")
        try:
            with os.fdopen(key_fd, "w") as fh:
                key_content = private_key.strip()
                if not key_content.endswith("\n"):
                    key_content += "\n"
                fh.write(key_content)
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

            git_ssh_cmd = (
                f"ssh -i {key_path} -o StrictHostKeyChecking=no "
                f"-o BatchMode=yes -o ConnectTimeout=8"
            )
            env = {**os.environ, "GIT_SSH_COMMAND": git_ssh_cmd, "GIT_TERMINAL_PROMPT": "0"}
            return self._run_ls_remote(repo_url, env, safe_url)
        finally:
            if os.path.exists(key_path):
                os.unlink(key_path)

    def _run_ls_remote(
        self, repo_url: str, env: Dict[str, str], safe_url: str
    ) -> ValidationResult:
        """Execute ``git ls-remote <url> HEAD`` and interpret the result.

        Args:
            repo_url: The actual URL passed to git (may contain embedded user
                      for PAT flow or be an SSH URL).
            env: Environment dict injected into the subprocess.
            safe_url: Credential-stripped URL used only for log messages.

        Returns:
            ValidationResult
        """
        logger.info("GitValidator: running git ls-remote for %s", safe_url)
        try:
            proc = subprocess.run(
                ["git", "ls-remote", repo_url, "HEAD"],
                capture_output=True,
                text=True,
                timeout=_GIT_TIMEOUT_SECONDS,
                env=env,
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                "GitValidator: git ls-remote timed out after %ds for %s",
                _GIT_TIMEOUT_SECONDS,
                safe_url,
            )
            return self._create_error_result(
                f"Repository connectivity check timed out after {_GIT_TIMEOUT_SECONDS}s",
                errors=["git ls-remote timed out"],
            )
        except FileNotFoundError:
            return self._create_error_result(
                "git executable not found on the server",
                errors=["git not installed"],
            )

        if proc.returncode != 0:
            stderr_safe = self._redact_stderr(proc.stderr or "")
            logger.warning(
                "GitValidator: git ls-remote failed (rc=%d) for %s: %s",
                proc.returncode,
                safe_url,
                stderr_safe,
            )
            return self._create_error_result(
                f"Repository authentication failed: {stderr_safe[:200] or 'check credentials'}",
                errors=[stderr_safe[:500]],
            )

        account_number = self._extract_account_number(repo_url)
        logger.info(
            "GitValidator: validated %s → account_number=%s", safe_url, account_number
        )
        return self._create_success_result(
            message=f"Git repository validated successfully ({account_number})",
            account_number=account_number,
        )
