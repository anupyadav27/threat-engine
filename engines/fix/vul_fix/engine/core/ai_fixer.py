"""
Mistral AI integration — generates Ansible playbooks for CVE remediation.

fix_package_ansible() sends Mistral:
  - OS / architecture / environment type (from scan system_info + vul_agent_id)
  - Package name + current version + known fixed version hint
  - All CVEs affecting this package (id, severity, CVSS score, description)
  - Organisation Ansible repo context (structure, conventions, existing task snippet)

Returns a raw YAML string (the Ansible playbook).
Raises ValueError if MISTRAL_API_KEY is not set.

Retry logic: validate → if errors, call fix_package_ansible() again with
error_context kwarg so Mistral can self-correct (max retries controlled by router).
"""

import logging
import os
import re
import time
from typing import Optional

import requests

from core.git_connector import AnsibleRepoContext

logger = logging.getLogger(__name__)

MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"

# Statuses that are transient and safe to retry
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MISTRAL_MAX_RETRIES = 3
_MISTRAL_BACKOFF_BASE = 2  # seconds — doubled each attempt (2 → 4 → 8)

_PRIORITY_MAP = {
    "CRITICAL": "immediate",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
}

_PACKAGE_MANAGER_MAP = {
    "ubuntu":   "apt-get",
    "debian":   "apt-get",
    "centos":   "yum",
    "rhel":     "yum",
    "fedora":   "dnf",
    "amazon":   "yum",
    "amzn":     "yum",
    "windows":  "choco",
    "alpine":   "apk",
    "arch":     "pacman",
    "suse":     "zypper",
    "opensuse": "zypper",
}

_ENV_CONTEXT_MAP = {
    "docker":     "Docker container",
    "container":  "Docker container",
    "k8s":        "Kubernetes pod",
    "kubernetes": "Kubernetes pod",
    "aws":        "AWS EC2 instance",
    "aws-ec2":    "AWS EC2 instance",
    "ec2":        "AWS EC2 instance",
    "azure":      "Azure VM",
    "gcp":        "GCP Compute instance",
    "vm":         "Virtual machine",
    "bare-metal": "Bare-metal server",
    "baremetal":  "Bare-metal server",
    "unknown":    "Linux system",
}


def _detect_package_manager(os_id: str, platform: str = "") -> str:
    for text in [os_id, platform]:
        p = (text or "").lower()
        for keyword, pm in _PACKAGE_MANAGER_MAP.items():
            if keyword in p:
                return pm
    return "apt-get"


def _env_description(env_type: str) -> str:
    et = (env_type or "unknown").lower()
    for key, desc in _ENV_CONTEXT_MAP.items():
        if key in et:
            return desc
    return f"{env_type} environment"


def _top_severity(cves: list) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severities = {(c.get("severity") or "").upper() for c in cves}
    for s in order:
        if s in severities:
            return s
    return "LOW"


def _sanitize(text: str) -> str:
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', ' ', (text or "").strip())


def _ansible_module_for_pm(pkg_manager: str, fqcn: bool = True) -> str:
    mapping = {
        "apt-get": "ansible.builtin.apt"     if fqcn else "apt",
        "yum":     "ansible.builtin.yum"     if fqcn else "yum",
        "dnf":     "ansible.builtin.dnf"     if fqcn else "dnf",
        "apk":     "community.general.apk",
        "pacman":  "community.general.pacman",
        "zypper":  "community.general.zypper",
        "choco":   "chocolatey.chocolatey.win_chocolatey",
    }
    return mapping.get(pkg_manager, "ansible.builtin.package" if fqcn else "package")


def _strip_yaml_fences(text: str) -> str:
    """Remove ```yaml / ```yml / ``` fences the AI may wrap around output."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        start = 1
        end = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
        text = "\n".join(lines[start:end])
    return text.strip()


def fix_package_ansible(
    package_name: str,
    package_version: str,
    cves: list,
    ansible_ctx: AnsibleRepoContext,
    system_info: Optional[dict] = None,
    platform: Optional[str] = None,
    hostname: Optional[str] = None,
    fixed_version_hint: Optional[str] = None,
    os_name: Optional[str] = None,
    os_version: Optional[str] = None,
    env_type: Optional[str] = None,
    hosts_pattern: str = "all",
    error_context: Optional[str] = None,
) -> str:
    """
    Call Mistral AI to generate an Ansible playbook that patches one package.

    Returns:
        YAML string — the complete Ansible playbook, always ending with newline.

    Raises:
        ValueError:   if MISTRAL_API_KEY is not set.
        RuntimeError: if Mistral API call fails.
    """
    api_key = os.getenv("MISTRAL_API_KEY", "").strip()
    if not api_key:
        raise ValueError("MISTRAL_API_KEY is not set.")

    model   = os.getenv("MISTRAL_MODEL",   "mistral-medium")
    timeout = int(os.getenv("MISTRAL_TIMEOUT", "90"))

    # ── System context ────────────────────────────────────────────────────────
    si           = system_info or {}
    host         = hostname or si.get("hostname", "unknown")
    architecture = si.get("architecture") or si.get("machine") or "x86_64"
    _os_name     = os_name    or si.get("os_name")    or si.get("os_id") or platform or "linux"
    _os_version  = os_version or si.get("os_version") or si.get("version") or ""
    _os_id       = si.get("os_id") or platform or _os_name.lower()
    os_label     = f"{_os_name} {_os_version}".strip()

    pkg_manager    = _detect_package_manager(_os_id, platform or "")
    ansible_module = _ansible_module_for_pm(pkg_manager, fqcn=ansible_ctx.fqcn_required)
    _env_type      = env_type or "unknown"
    env_desc       = _env_description(_env_type)

    # ── CVE list ──────────────────────────────────────────────────────────────
    cve_lines = []
    for c in cves:
        cve_id = c.get("cve_id", "")
        sev    = (c.get("severity") or "UNKNOWN").upper()
        score  = c.get("cvss_v3_score") or c.get("score") or "N/A"
        desc   = _sanitize(c.get("cve_description") or c.get("sv_description") or "")
        cve_lines.append(f"  - {cve_id} [{sev}, CVSS {score}]: {desc[:150]}")

    cve_text   = "\n".join(cve_lines)
    top_sev    = _top_severity(cves)
    priority   = _PRIORITY_MAP.get(top_sev, "medium")
    # Only provide fixed version hint when it is confirmed — never let AI guess
    fixed_hint = (
        f"\nConfirmed patched version available: {fixed_version_hint}"
        if fixed_version_hint else
        "\nNo confirmed patched version in database — use state: latest."
    )

    # ── Ansible repo conventions ──────────────────────────────────────────────
    repo_context_block = f"""
## Organisation Ansible Repo Conventions
- Structure     : {ansible_ctx.structure_type}
- Ansible ver   : {ansible_ctx.ansible_version or 'unknown — assume modern, use FQCN'}
- FQCN required : {'yes — always prefix with ansible.builtin.* or community.general.*' if ansible_ctx.fqcn_required else 'no — short module names acceptable'}
- Become method : {ansible_ctx.become_method}
- Remote user   : {ansible_ctx.remote_user or '(not set — Ansible default)'}
- Vault present : {'yes — do NOT hardcode secrets; reference vault variables' if ansible_ctx.has_vault else 'no'}
- Existing roles: {', '.join(ansible_ctx.existing_roles[:8]) or 'none'}

### Existing package task pattern from this repo (match this style exactly):
```yaml
{ansible_ctx.package_task_snippet}
```
"""

    group_vars_block = ""
    if ansible_ctx.group_vars_snippet:
        group_vars_block = f"""
### Relevant group_vars (use these variable names where applicable):
```yaml
{ansible_ctx.group_vars_snippet[:600]}
```
"""

    # ── Environment-specific instructions ─────────────────────────────────────
    et_lower  = _env_type.lower()
    env_notes = ""
    if "docker" in et_lower or "container" in et_lower:
        env_notes = (
            "\nENV NOTE: This is a Docker container. "
            "Runtime package upgrades are NOT persistent across restarts. "
            "After the upgrade tasks, add a clearly commented block showing "
            "the equivalent Dockerfile RUN line the team must add to their image. "
            "This Dockerfile block must be a YAML comment, not a task."
        )
    elif "k8s" in et_lower or "kubernetes" in et_lower:
        env_notes = (
            "\nENV NOTE: This is a Kubernetes pod. "
            "After upgrade tasks, add a commented block showing the kubectl rollout "
            "restart command the team must run after updating the container image."
        )
    elif "aws" in et_lower or "ec2" in et_lower:
        env_notes = (
            "\nENV NOTE: This is an AWS EC2 instance. "
            "After upgrade tasks, add a comment block advising the team to "
            "bake a new AMI so new instances are not deployed with the vulnerable package."
        )

    # ── Retry error context ───────────────────────────────────────────────────
    retry_block = ""
    if error_context:
        retry_block = f"""
## ERRORS FROM YOUR PREVIOUS ATTEMPT — YOU MUST FIX ALL OF THESE:
{error_context}

"""

    # ── Build prompt ──────────────────────────────────────────────────────────
    prompt = f"""You are a senior Ansible automation engineer and cybersecurity expert.
Write a complete, production-ready Ansible playbook to patch a vulnerable package.
This playbook will be REVIEWED BY HUMANS before execution — never add auto-execution triggers.
{retry_block}
## Target System
- Hostname      : {host}
- OS            : {os_label}
- Architecture  : {architecture}
- Environment   : {env_desc}
- Pkg manager   : {pkg_manager}
- Ansible module: {ansible_module}
- Hosts pattern : {hosts_pattern}
{env_notes}
{repo_context_block}{group_vars_block}
## Vulnerable Package
- Name          : {package_name}
- Installed ver : {package_version or 'unknown'}{fixed_hint}
- Priority      : {priority}

## CVEs to Remediate ({len(cves)} total)
{cve_text}

## Strict Playbook Requirements — follow ALL of these exactly:

### Task ordering (CRITICAL — do not change this order):
1. FIRST task MUST be `ansible.builtin.package_facts` with `manager: auto`
   This MUST come before ANY task that references `ansible_facts.packages`.
   Failure to do this causes a runtime KeyError crash.

2. SECOND task: debug the current installed version using:
   `ansible_facts.packages['{package_name}'][0].version`
   (safe because package_facts was already gathered in task 1)

3. Update package cache (apt-get update equivalent for this OS).

4. Upgrade the package:
   - If a confirmed patched version is provided above: pin to that exact version.
   - If NO confirmed version is provided: use `state: latest` — NEVER invent a version number.
     Inventing a version number will cause `apt-get` to fail with "no installation candidate".

5. Gather package_facts AGAIN after upgrade (so assert has fresh data).

6. Assert the package is no longer on the vulnerable version:
   - Check: `ansible_facts.packages['{package_name}'][0].version != vulnerable_version`
   - Use `fail_msg` and `success_msg` for clarity.

### Handlers (CRITICAL rules):
- If dependent services are known (e.g. nginx, sshd): create a named handler per service.
- If dependent services are UNKNOWN: create ONE commented-out handler block as a YAML comment.
  Do NOT create a handler with `when: false` or an empty loop — this is broken and never runs.
  A handler with `when: false` is permanently disabled and provides false confidence.

### Other requirements:
- `become: true` at the play level (not per-task) if become_method is sudo.
- `vars` block with: `package_name`, `vulnerable_version`, `expected_fixed_version`
  (if version unknown, set expected_fixed_version to "latest" as a string placeholder).
- Tags on EVERY task: `security`, `patch`, and one tag per CVE id (lowercase, e.g. `cve-2024-1234`).
- Top-of-file YAML comment block listing: all CVE IDs, severities, scan_id, generated timestamp.
- Match the existing repo task style exactly (indentation, module names, naming conventions).
- `gather_facts: true` (default — do NOT set to false, it is needed for OS detection).

## Output Rules
- Return ONLY the YAML playbook — NO markdown fences, NO explanation outside the YAML.
- Start with `---` (YAML document start marker).
- End the file with a single blank line (newline at end of file).
- Valid YAML that passes yamllint strict mode.
"""

    # ── Mistral API call with exponential backoff on transient errors ──────────
    payload = {
        "model":       model,
        "messages":    [{"role": "user", "content": prompt}],
        "temperature": 0.05,   # very low — deterministic code generation
        "max_tokens":  3500,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }

    last_exc: Exception = RuntimeError("Mistral call did not execute")
    for attempt in range(1, _MISTRAL_MAX_RETRIES + 1):
        try:
            resp = requests.post(
                MISTRAL_API_URL,
                headers=headers,
                json=payload,
                timeout=timeout,
            )

            # Transient server-side errors — back off and retry
            if resp.status_code in _RETRYABLE_STATUS and attempt < _MISTRAL_MAX_RETRIES:
                wait = _MISTRAL_BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning(
                    f"[AI] Mistral {resp.status_code} for '{package_name}' "
                    f"(attempt {attempt}/{_MISTRAL_MAX_RETRIES}) — retrying in {wait}s"
                )
                time.sleep(wait)
                continue

            resp.raise_for_status()
            raw           = resp.json()["choices"][0]["message"]["content"].strip()
            playbook_yaml = _strip_yaml_fences(raw)

            # Guarantee trailing newline (yamllint: new-line-at-end-of-file)
            if not playbook_yaml.endswith("\n"):
                playbook_yaml += "\n"

            logger.info(
                f"[AI] Playbook generated for '{package_name}' — "
                f"{len(cves)} CVE(s), priority={priority}, env={_env_type}, "
                f"{'retry' if error_context else 'first attempt'}"
                + (f" (Mistral attempt {attempt})" if attempt > 1 else "")
            )
            return playbook_yaml

        except requests.HTTPError as e:
            http_status = e.response.status_code if e.response is not None else "?"
            last_exc = RuntimeError(
                f"Mistral HTTP {http_status} for '{package_name}': {e}"
            )
            if http_status not in _RETRYABLE_STATUS or attempt == _MISTRAL_MAX_RETRIES:
                raise last_exc from e
            wait = _MISTRAL_BACKOFF_BASE * (2 ** (attempt - 1))
            logger.warning(
                f"[AI] Mistral HTTP {http_status} for '{package_name}' "
                f"(attempt {attempt}/{_MISTRAL_MAX_RETRIES}) — retrying in {wait}s"
            )
            time.sleep(wait)

        except requests.Timeout:
            last_exc = RuntimeError(
                f"Mistral timed out after {timeout}s for '{package_name}'"
            )
            if attempt == _MISTRAL_MAX_RETRIES:
                raise last_exc
            wait = _MISTRAL_BACKOFF_BASE * (2 ** (attempt - 1))
            logger.warning(
                f"[AI] Mistral timeout for '{package_name}' "
                f"(attempt {attempt}/{_MISTRAL_MAX_RETRIES}) — retrying in {wait}s"
            )
            time.sleep(wait)

        except Exception as e:
            raise RuntimeError(f"Mistral error for '{package_name}': {e}") from e

    raise last_exc
