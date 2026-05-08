"""
Git Repository Scanner

Accepts a Git repository URL, clones it (shallow), traverses all files,
detects every dependency manifest present, parses each one, and returns
a normalised component list ready for vulnerability enrichment.

No external SBOM tool (Syft, Trivy, cdxgen) is required.
The platform is fully self-contained.

Supported dependency manifests:
  Python     : requirements*.txt, Pipfile.lock, pyproject.toml, setup.cfg
  Node.js    : package.json, package-lock.json, yarn.lock
  Go         : go.mod
  Rust       : Cargo.toml, Cargo.lock
  Java       : pom.xml, build.gradle, build.gradle.kts
  Ruby       : Gemfile.lock
  .NET       : *.csproj, packages.config
  PHP        : composer.lock
"""

import json
import logging
import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Max repo size to clone (MB) — safety limit
MAX_REPO_SIZE_MB  = 500
CLONE_TIMEOUT_SEC = 120
# File size limit for individual manifest parsing (bytes)
MAX_FILE_SIZE     = 5 * 1024 * 1024  # 5 MB


# ── PURL builder ──────────────────────────────────────────────────────────────

def _purl(ecosystem: str, name: str, version: Optional[str]) -> Optional[str]:
    if not name:
        return None
    eco_map = {
        "PyPI":      ("pypi",     lambda n, _: n.lower()),
        "npm":       ("npm",      lambda n, _: n.lower()),
        "Go":        ("golang",   lambda n, _: n),
        "crates.io": ("cargo",    lambda n, _: n.lower()),
        "Maven":     ("maven",    _maven_purl_name),
        "RubyGems":  ("gem",      lambda n, _: n.lower()),
        "NuGet":     ("nuget",    lambda n, _: n.lower()),
        "Packagist": ("composer", lambda n, _: n.lower()),
    }
    entry = eco_map.get(ecosystem)
    if not entry:
        return None
    pkg_type, name_fn = entry
    pkg_name = name_fn(name, version)
    if version:
        return f"pkg:{pkg_type}/{pkg_name}@{version}"
    return f"pkg:{pkg_type}/{pkg_name}"


def _maven_purl_name(name: str, _) -> str:
    # name is already "groupId:artifactId" or just artifactId
    if ":" in name:
        group, artifact = name.split(":", 1)
        return f"{group}/{artifact}"
    return name


def _component(
    name: str,
    version: Optional[str],
    ecosystem: str,
    scope: str = "required",
    source_file: str = "",
) -> Dict:
    return {
        "name":           name,
        "version":        version,
        "ecosystem":      ecosystem,
        "purl":           _purl(ecosystem, name, version),
        "component_type": "library",
        "scope":          scope,
        "source_file":    source_file,
        "licenses":       [],
        "hashes":         [],
    }


# ── Individual file parsers ───────────────────────────────────────────────────

def _parse_requirements_txt(content: str, path: str) -> List[Dict]:
    """
    Parse requirements.txt (and requirements-*.txt, requirements/*.txt).
    Handles: pkg==1.2.3, pkg>=1.2.3, pkg~=1.2.3, pkg[extra]==1.2.3, -r other.txt
    """
    components = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip inline comment
        line = line.split("#")[0].strip()
        # Strip extras: requests[security] -> requests
        line = re.sub(r'\[.*?\]', '', line)
        # Match name with optional version specifier
        m = re.match(r'^([A-Za-z0-9_.-]+)\s*(?:[><=!~^]+\s*([\d][^\s,;]*?))?(?:\s*[,;].*)?$', line)
        if m:
            name    = m.group(1).strip()
            version = m.group(2).strip() if m.group(2) else None
            components.append(_component(name, version, "PyPI", source_file=path))
    return components


def _parse_pipfile_lock(content: str, path: str) -> List[Dict]:
    try:
        data = json.loads(content)
    except Exception:
        return []
    components = []
    for section in ("default", "develop"):
        scope = "required" if section == "default" else "optional"
        for name, meta in data.get(section, {}).items():
            version = meta.get("version", "").lstrip("=") or None
            components.append(_component(name, version, "PyPI", scope=scope, source_file=path))
    return components


def _parse_pyproject_toml(content: str, path: str) -> List[Dict]:
    """Parse pyproject.toml — supports both poetry and PEP 621 formats."""
    components = []
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            # Fallback: regex extraction (less accurate)
            return _parse_pyproject_toml_regex(content, path)

    try:
        data = tomllib.loads(content)
    except Exception:
        return []

    # Poetry: tool.poetry.dependencies
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, ver_spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        version = _clean_poetry_version(ver_spec)
        components.append(_component(name, version, "PyPI", source_file=path))

    # PEP 621: project.dependencies (list of "pkg>=1.0" strings)
    for dep_str in data.get("project", {}).get("dependencies", []):
        m = re.match(r'^([A-Za-z0-9_.-]+)\s*(?:[><=!~^]+\s*([\d][^\s,;]*))?', dep_str.strip())
        if m:
            components.append(_component(m.group(1), m.group(2), "PyPI", source_file=path))

    return components


def _parse_pyproject_toml_regex(content: str, path: str) -> List[Dict]:
    components = []
    for m in re.finditer(r'"([A-Za-z0-9_.-]+)\s*(?:[><=!~^]+\s*([\d][^"]*?))?"\s*[,\n]', content):
        components.append(_component(m.group(1), m.group(2), "PyPI", source_file=path))
    return components


def _clean_poetry_version(spec) -> Optional[str]:
    if isinstance(spec, str):
        return re.sub(r'^[^0-9]*', '', spec.split(",")[0]) or None
    if isinstance(spec, dict):
        v = spec.get("version", "")
        return re.sub(r'^[^0-9]*', '', v) or None
    return None


def _parse_setup_cfg(content: str, path: str) -> List[Dict]:
    """
    Parse setup.cfg — reads [options] install_requires and extras_require sections.
    Format:
        [options]
        install_requires =
            requests>=2.25.0
            Flask>=2.0
    """
    import configparser
    components = []
    cfg = configparser.ConfigParser()
    try:
        cfg.read_string(content)
    except Exception:
        return []

    # Collect from install_requires (required) and extras_require (optional)
    def _extract_from_block(raw: str, scope: str):
        for line in raw.splitlines():
            dep = line.strip().split(";")[0].strip()   # strip environment markers
            dep = re.sub(r'\[.*?\]', '', dep)          # strip extras
            m = re.match(r'^([A-Za-z0-9_.-]+)\s*(?:[><=!~^]+\s*([\d][^\s,]*))?', dep)
            if m and m.group(1):
                components.append(_component(m.group(1), m.group(2), "PyPI",
                                             scope=scope, source_file=path))

    if cfg.has_option("options", "install_requires"):
        _extract_from_block(cfg.get("options", "install_requires"), "required")

    if cfg.has_section("options.extras_require"):
        for _key, val in cfg.items("options.extras_require"):
            _extract_from_block(val, "optional")

    return components


def _parse_package_json(content: str, path: str) -> List[Dict]:
    try:
        data = json.loads(content)
    except Exception:
        return []

    # Skip if this is a lock file (package-lock.json parsed separately)
    if "lockfileVersion" in data:
        return []

    components = []
    for dep_type in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        scope = "optional" if dep_type in ("devDependencies", "optionalDependencies") else "required"
        for name, ver_spec in data.get(dep_type, {}).items():
            version = _clean_npm_version(ver_spec)
            components.append(_component(name, version, "npm", scope=scope, source_file=path))
    return components


def _parse_package_lock_json(content: str, path: str) -> List[Dict]:
    """package-lock.json gives resolved (exact) versions — more accurate."""
    try:
        data = json.loads(content)
    except Exception:
        return []

    components = []
    # v2/v3 format: packages dict
    packages = data.get("packages", {})
    for pkg_path, meta in packages.items():
        if not pkg_path or pkg_path == "":
            continue  # skip root
        # pkg_path like "node_modules/lodash" or "node_modules/@types/node"
        name = pkg_path.replace("node_modules/", "").lstrip("/")
        version = meta.get("version")
        scope = "optional" if meta.get("dev") else "required"
        components.append(_component(name, version, "npm", scope=scope, source_file=path))
    return components


def _parse_yarn_lock(content: str, path: str) -> List[Dict]:
    components = []
    current_name = None
    for line in content.splitlines():
        # Package header: "lodash@^4.17.21":
        m = re.match(r'^"?(@?[a-zA-Z0-9_/@.-]+)@[^"]*"?:?$', line)
        if m:
            current_name = m.group(1).split("@")[0] if not m.group(1).startswith("@") else m.group(1)
            continue
        # Version line:   version "4.17.21"
        mv = re.match(r'^\s+version\s+"([^"]+)"', line)
        if mv and current_name:
            components.append(_component(current_name, mv.group(1), "npm", source_file=path))
            current_name = None
    return components


def _clean_npm_version(ver: str) -> Optional[str]:
    if not ver or ver in ("*", "latest", "next", ""):
        return None
    # Remove range prefixes: ^1.2.3 ~1.2.3 >=1.2.3
    cleaned = re.sub(r'^[^0-9]*', '', ver.split(" ")[0])
    return cleaned or None


def _parse_go_mod(content: str, path: str) -> List[Dict]:
    components = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        target = stripped if (in_require or stripped.startswith("require ")) else None
        if target:
            target = re.sub(r'^require\s+', '', target)
            target = target.split("//")[0].strip()  # strip inline comment
            m = re.match(r'^([\w./\-@]+)\s+v([\d][^\s]*)', target)
            if m:
                components.append(_component(m.group(1), m.group(2), "Go", source_file=path))
    return components


def _parse_cargo_toml(content: str, path: str) -> List[Dict]:
    components = []
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return _parse_cargo_toml_regex(content, path)

    try:
        data = tomllib.loads(content)
    except Exception:
        return _parse_cargo_toml_regex(content, path)

    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        scope = "optional" if section != "dependencies" else "required"
        for name, spec in data.get(section, {}).items():
            if isinstance(spec, str):
                version = re.sub(r'^[^0-9]*', '', spec) or None
            elif isinstance(spec, dict):
                version = spec.get("version")
                if version:
                    version = re.sub(r'^[^0-9]*', '', version) or None
            else:
                version = None
            components.append(_component(name, version, "crates.io", scope=scope, source_file=path))
    return components


_CARGO_META_KEYS = {
    "name", "version", "edition", "authors", "description",
    "license", "readme", "repository", "homepage", "documentation",
    "build", "workspace", "resolver", "publish",
}


def _parse_cargo_toml_regex(content: str, path: str) -> List[Dict]:
    """Regex fallback for when tomllib is unavailable (Python < 3.11)."""
    components = []
    in_dep_section = False
    for line in content.splitlines():
        stripped = line.strip()
        if re.match(r'^\[(dependencies|dev-dependencies|build-dependencies)\]', stripped):
            in_dep_section = True
            continue
        if stripped.startswith("[") and in_dep_section:
            in_dep_section = False
        if not in_dep_section:
            continue
        m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', stripped)
        if m:
            pkg_name = m.group(1)
            if pkg_name in _CARGO_META_KEYS:
                continue
            version = re.sub(r'^[^0-9]*', '', m.group(2)) or None
            components.append(_component(pkg_name, version, "crates.io", source_file=path))
    return components


def _parse_cargo_lock(content: str, path: str) -> List[Dict]:
    """Cargo.lock has exact resolved versions."""
    components = []
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return []
    try:
        data = tomllib.loads(content)
    except Exception:
        return []
    for pkg in data.get("package", []):
        name    = pkg.get("name")
        version = pkg.get("version")
        if name:
            components.append(_component(name, version, "crates.io", source_file=path))
    return components


def _parse_pom_xml(content: str, path: str) -> List[Dict]:
    components = []
    try:
        root = ET.fromstring(content)
    except Exception:
        return []
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}

    def _find_text(el, tag):
        # NOTE: must use `is not None` — ET elements are falsy if they have no children
        child = el.find(f"m:{tag}", ns)
        if child is None:
            child = el.find(tag)
        return child.text.strip() if child is not None and child.text else None

    # Properties for version variable substitution
    props: Dict[str, str] = {}
    props_el = root.find("m:properties", ns) or root.find("properties")
    if props_el is not None:
        for prop in props_el:
            tag = prop.tag.split("}")[-1] if "}" in prop.tag else prop.tag
            props[tag] = (prop.text or "").strip()

    for dep_el in root.iter("{http://maven.apache.org/POM/4.0.0}dependency"):
        group_id    = _find_text(dep_el, "groupId")    or ""
        artifact_id = _find_text(dep_el, "artifactId") or ""
        raw_version = _find_text(dep_el, "version")    or ""
        scope_txt   = (_find_text(dep_el, "scope") or "compile").lower()

        if not artifact_id:
            continue

        # Resolve ${property} references
        version = raw_version
        if version.startswith("${"):
            key = version[2:-1]
            version = props.get(key, version)
        version = re.sub(r'[\[\]()]', '', version).split(",")[0].strip() or None
        if version and not re.match(r'^\d', version):
            version = None

        name = f"{group_id}:{artifact_id}" if group_id else artifact_id
        scope = "optional" if scope_txt in ("test", "provided") else "required"
        components.append(_component(name, version, "Maven", scope=scope, source_file=path))

    return components


def _parse_build_gradle(content: str, path: str) -> List[Dict]:
    components = []
    # Match: implementation 'com.google.guava:guava:31.1-jre'
    #        compile group: 'x', name: 'y', version: 'z'
    for m in re.finditer(
        r'''(?:implementation|compile|api|runtimeOnly|testImplementation)\s+
            ['"]([^'"]+)['"]''',
        content, re.VERBOSE,
    ):
        parts = m.group(1).split(":")
        if len(parts) >= 2:
            name    = f"{parts[0]}:{parts[1]}"
            version = parts[2] if len(parts) >= 3 else None
            components.append(_component(name, version, "Maven", source_file=path))
    return components


def _parse_gemfile_lock(content: str, path: str) -> List[Dict]:
    components = []
    in_gems = False
    for line in content.splitlines():
        if line.strip() == "GEM":
            in_gems = True
            continue
        if in_gems and re.match(r'^[A-Z]', line):
            in_gems = False
            continue
        if in_gems:
            m = re.match(r'^\s{4}([a-zA-Z0-9_-]+)\s+\(([\d][^)]*)\)', line)
            if m:
                components.append(_component(m.group(1), m.group(2), "RubyGems", source_file=path))
    return components


def _parse_csproj(content: str, path: str) -> List[Dict]:
    components = []
    try:
        root = ET.fromstring(content)
    except Exception:
        return []
    for ref in root.iter("PackageReference"):
        name    = ref.get("Include") or ref.get("include") or ""
        version = ref.get("Version") or ref.get("version") or ""
        if name:
            components.append(_component(name, version or None, "NuGet", source_file=path))
    return components


def _parse_packages_config(content: str, path: str) -> List[Dict]:
    components = []
    try:
        root = ET.fromstring(content)
    except Exception:
        return []
    for pkg in root.iter("package"):
        name    = pkg.get("id", "")
        version = pkg.get("version", "")
        if name:
            components.append(_component(name, version or None, "NuGet", source_file=path))
    return components


def _parse_composer_lock(content: str, path: str) -> List[Dict]:
    try:
        data = json.loads(content)
    except Exception:
        return []
    components = []
    for pkg in data.get("packages", []) + data.get("packages-dev", []):
        name    = pkg.get("name", "")
        version = pkg.get("version", "").lstrip("v") or None
        if name:
            components.append(_component(name, version, "Packagist", source_file=path))
    return components


# ── File type detection ───────────────────────────────────────────────────────

def _classify_file(rel_path: str) -> Optional[str]:
    """Map a relative file path to a parser key. Returns None if not relevant."""
    filename = Path(rel_path).name
    lower    = filename.lower()

    if re.match(r'^requirements.*\.txt$', lower):
        return "requirements_txt"
    if lower == "pipfile.lock":
        return "pipfile_lock"
    if lower == "pyproject.toml":
        return "pyproject_toml"
    if lower == "setup.cfg":
        return "setup_cfg"
    if lower == "package-lock.json":
        return "package_lock_json"
    if lower == "package.json":
        return "package_json"
    if lower == "yarn.lock":
        return "yarn_lock"
    if lower == "go.mod":
        return "go_mod"
    if lower == "cargo.lock":
        return "cargo_lock"
    if lower == "cargo.toml":
        return "cargo_toml"
    if lower == "pom.xml":
        return "pom_xml"
    if lower in ("build.gradle", "build.gradle.kts"):
        return "build_gradle"
    if lower == "gemfile.lock":
        return "gemfile_lock"
    if lower.endswith(".csproj"):
        return "csproj"
    if lower == "packages.config":
        return "packages_config"
    if lower == "composer.lock":
        return "composer_lock"

    return None


_PARSERS = {
    "requirements_txt": _parse_requirements_txt,
    "pipfile_lock":      _parse_pipfile_lock,
    "pyproject_toml":    _parse_pyproject_toml,
    "setup_cfg":         _parse_setup_cfg,
    "package_lock_json": _parse_package_lock_json,
    "package_json":      _parse_package_json,
    "yarn_lock":         _parse_yarn_lock,
    "go_mod":            _parse_go_mod,
    "cargo_lock":        _parse_cargo_lock,
    "cargo_toml":        _parse_cargo_toml,
    "pom_xml":           _parse_pom_xml,
    "build_gradle":      _parse_build_gradle,
    "gemfile_lock":      _parse_gemfile_lock,
    "csproj":            _parse_csproj,
    "packages_config":   _parse_packages_config,
    "composer_lock":     _parse_composer_lock,
}

# When both are present prefer lock files (exact versions)
_LOCK_PRECEDENCE = {
    "package_json":  "package_lock_json",  # prefer lock
    "cargo_toml":    "cargo_lock",
}

# Directories to skip
_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", ".env",
    "__pycache__", ".tox", ".pytest_cache", "dist", "build",
    "target",  # Rust/Java
    "vendor",  # Go/PHP
    ".idea", ".vscode",
}


# ── Main scanner class ────────────────────────────────────────────────────────

class GitRepoScanner:
    """
    Clones a Git repository and extracts all software components by parsing
    every dependency manifest found in the repository tree.
    """

    def scan(
        self,
        git_url: str,
        branch: Optional[str] = None,
        git_token: Optional[str] = None,
        git_username: Optional[str] = None,
    ) -> Dict:
        """
        Clone + scan a Git repository.

        Args:
          git_url      : Public or private HTTPS / SSH git URL.
          branch       : Branch to clone (default branch if None).
          git_token    : Personal Access Token / OAuth token for private repos.
                         Supported providers: GitHub, GitLab, Bitbucket,
                         Azure DevOps, and any self-hosted HTTPS git server.
                         NEVER logged, stored, or returned in responses.
          git_username : Username — required for Bitbucket App Passwords and
                         self-hosted servers that need user:token format.

        Returns:
          {
            "application_name": str,
            "components":       [component dicts],
            "detected_files":   [{"path": ..., "type": ..., "count": ...}],
            "languages":        [str],
            "commit_sha":       str,
            "repo_url":         git_url,   # always the clean URL — no token
          }
        Raises ValueError on invalid URL or token + SSH combination.
        Raises RuntimeError on clone failure.
        """
        _validate_git_url(git_url)
        app_name = _repo_name_from_url(git_url)

        # Build authenticated clone URL (token injected only here, never stored)
        clone_url = _build_auth_url(git_url, git_token, git_username) if git_token else git_url

        with tempfile.TemporaryDirectory(prefix="sbom_clone_") as tmp_dir:
            commit_sha = self._clone(clone_url, git_url, tmp_dir, branch)
            result     = self._scan_directory(tmp_dir, app_name, git_url, commit_sha)

        return result

    def _clone(self, clone_url: str, display_url: str, dest: str, branch: Optional[str]) -> str:
        cmd = ["git", "clone", "--depth=1", "--single-branch"]
        if branch:
            cmd += ["--branch", branch]
        cmd += [clone_url, dest]

        logger.info(f"Cloning {display_url} ...")   # clean URL — token never logged
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                timeout=CLONE_TIMEOUT_SEC,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode(errors="replace")[:500]
            # Scrub credentials from git error messages before surfacing to caller.
            # Two passes: replace the full auth URL, then replace the raw token
            # in case git reformats the URL differently in its error output.
            if clone_url != display_url:
                err = err.replace(clone_url, display_url)
                # Extract credential portion (between :// and @) and scrub directly
                import urllib.parse as _up
                _parsed = _up.urlparse(clone_url)
                if _parsed.password:
                    err = err.replace(_parsed.password, "***")
                if _parsed.username and _parsed.username != _parsed.hostname:
                    err = err.replace(_parsed.username, "***")
            raise RuntimeError(f"Git clone failed: {err}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Git clone timed out after {CLONE_TIMEOUT_SEC}s")

        # Get commit SHA
        try:
            r = subprocess.run(
                ["git", "-C", dest, "rev-parse", "HEAD"],
                capture_output=True, timeout=10,
            )
            return r.stdout.decode().strip()[:40]
        except Exception:
            return "unknown"

    def _scan_directory(
        self, root: str, app_name: str, git_url: str, commit_sha: str
    ) -> Dict:
        root_path = Path(root)
        found_files: List[Tuple[str, str]] = []  # (rel_path, file_type)

        # Walk the repo and collect relevant files
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skip dirs in-place
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                rel  = os.path.relpath(full, root)
                ftype = _classify_file(rel)
                if ftype:
                    found_files.append((rel, ftype))

        # Resolve lock-file precedence
        # e.g. if Cargo.lock exists, skip Cargo.toml
        found_types = {ft for _, ft in found_files}
        skip_types: set = set()
        for base, preferred in _LOCK_PRECEDENCE.items():
            if preferred in found_types:
                skip_types.add(base)

        # Parse each file
        all_components: List[Dict] = []
        detected_files: List[Dict] = []

        for rel_path, ftype in found_files:
            if ftype in skip_types:
                continue
            full_path = root_path / rel_path
            try:
                if full_path.stat().st_size > MAX_FILE_SIZE:
                    logger.warning(f"Skipping oversized file: {rel_path}")
                    continue
                content  = full_path.read_text(encoding="utf-8", errors="replace")
                parser   = _PARSERS[ftype]
                comps    = parser(content, rel_path)
                all_components.extend(comps)
                detected_files.append({
                    "path":  rel_path,
                    "type":  ftype,
                    "count": len(comps),
                })
                logger.info(f"  {rel_path}: {len(comps)} components ({ftype})")
            except Exception as e:
                logger.warning(f"Parse error in {rel_path}: {e}")

        # Deduplicate: same (name, ecosystem) — prefer entry with a version
        deduped = _deduplicate(all_components)

        # Detect languages from what we found
        languages = _detect_languages(detected_files)

        return {
            "application_name": app_name,
            "components":       deduped,
            "detected_files":   detected_files,
            "languages":        languages,
            "commit_sha":       commit_sha,
            "repo_url":         git_url,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_auth_url(url: str, token: str, username: Optional[str] = None) -> str:
    """
    Inject credentials into an HTTPS git URL for private repo cloning.

    The returned URL is used ONLY inside the git clone subprocess — it is
    never logged, stored in the database, or returned to the API caller.

    Provider behaviour:
      GitHub / GitHub Enterprise : https://<token>@github.com/...
      GitLab / GitLab self-hosted: https://oauth2:<token>@gitlab.com/...
      Bitbucket Cloud            : https://x-token-auth:<token>@bitbucket.org/...
      Azure DevOps               : https://<username>:<token>@dev.azure.com/...
      Gitea / Forgejo / others   : https://<username>:<token>@<host>/...
                                   (username required for generic self-hosted)

    Raises ValueError if the URL is SSH-based (git@...) — SSH repos require
    an SSH key mounted in the container, not a token.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if not parsed.scheme.startswith("http"):
        raise ValueError(
            "Token authentication requires an HTTPS git URL. "
            "SSH URLs (git@...) need an SSH key configured in the container instead."
        )

    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""

    if "github.com" in host or ("github." in host and "gitlab" not in host):
        creds = token                               # GitHub: token as username
    elif "gitlab.com" in host or "gitlab." in host:
        creds = f"oauth2:{token}"                  # GitLab: oauth2:token
    elif "bitbucket.org" in host:
        creds = f"x-token-auth:{token}"            # Bitbucket: x-token-auth:token
    elif "dev.azure.com" in host or "visualstudio.com" in host:
        creds = f"{username or 'pat'}:{token}"     # Azure DevOps: user:PAT
    else:
        # Self-hosted: prefer user:token when username given, else token only
        creds = f"{username}:{token}" if username else token

    auth_url = f"{parsed.scheme}://{creds}@{host}{port}{parsed.path}"
    if parsed.query:
        auth_url += f"?{parsed.query}"
    return auth_url


def _validate_git_url(url: str):
    """Allow only HTTPS/HTTP/SSH git URLs — prevent command injection."""
    url = url.strip()
    if not url:
        raise ValueError("Git URL cannot be empty")
    if not re.match(
        r'^(https?://|git@|ssh://)[^\s;|&`$<>]+$',
        url,
    ):
        raise ValueError(
            "Invalid Git URL. Only HTTPS, HTTP, or SSH git URLs are allowed. "
            f"Received: {url[:100]}"
        )


def _repo_name_from_url(url: str) -> str:
    """Extract repository name from URL: https://github.com/owner/myapp.git → myapp"""
    name = url.rstrip("/").split("/")[-1]
    return re.sub(r'\.git$', '', name) or "unknown"


def _deduplicate(components: List[Dict]) -> List[Dict]:
    """
    Deduplicate components by (name_lower, ecosystem).
    Prefer entries with a version; prefer lock file entries over manifests.
    """
    seen: Dict[Tuple[str, str], Dict] = {}
    for comp in components:
        key = (comp["name"].lower(), comp.get("ecosystem", ""))
        existing = seen.get(key)
        if existing is None:
            seen[key] = comp
        elif not existing.get("version") and comp.get("version"):
            # Replace no-version entry with versioned entry
            seen[key] = comp
    return list(seen.values())


def _detect_languages(detected_files: List[Dict]) -> List[str]:
    lang_map = {
        "requirements_txt": "Python",
        "pipfile_lock":      "Python",
        "pyproject_toml":    "Python",
        "setup_cfg":         "Python",
        "package_json":      "JavaScript/Node.js",
        "package_lock_json": "JavaScript/Node.js",
        "yarn_lock":         "JavaScript/Node.js",
        "go_mod":            "Go",
        "cargo_toml":        "Rust",
        "cargo_lock":        "Rust",
        "pom_xml":           "Java",
        "build_gradle":      "Java/Kotlin",
        "gemfile_lock":      "Ruby",
        "csproj":            ".NET/C#",
        "packages_config":   ".NET/C#",
        "composer_lock":     "PHP",
    }
    langs = []
    for f in detected_files:
        lang = lang_map.get(f["type"])
        if lang and lang not in langs:
            langs.append(lang)
    return langs
