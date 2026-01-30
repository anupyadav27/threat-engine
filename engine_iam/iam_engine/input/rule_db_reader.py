"""
Read metadata from rule database and identify IAM-relevant rules.

IAM-relevant = domain == 'identity_and_access_management' in metadata.
Supports rule_db paths: engine_check/engine_check_aws/services or .../rule_db/default/services.
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import logging

logger = logging.getLogger(__name__)

IAM_DOMAIN = "identity_and_access_management"

# IAM module names derived from assertion_id / rule_id patterns
IAM_MODULES = [
    "least_privilege",
    "policy_analysis",
    "mfa",
    "role_management",
    "password_policy",
    "access_control",
]


def _derive_iam_modules(rule_id: str, metadata: Dict) -> List[str]:
    """Derive IAM module list from rule_id and metadata."""
    modules = []
    text = f"{rule_id} {metadata.get('assertion_id', '')} {metadata.get('rationale', '')}".lower()
    if "least_privilege" in text or "rbac" in text or "least_privilege" in text:
        modules.append("least_privilege")
    if "policy" in text or "policy_" in rule_id:
        modules.append("policy_analysis")
    if "mfa" in text or "multi_factor" in text or "hardware_mfa" in text:
        modules.append("mfa")
    if "role" in text or "iam_role" in rule_id:
        modules.append("role_management")
    if "password" in text or "password_policy" in rule_id:
        modules.append("password_policy")
    if "access" in text or "rbac" in text:
        modules.append("access_control")
    if not modules:
        modules.append("access_control")
    return list(dict.fromkeys(modules))


class RuleDBReader:
    """Reads metadata from rule database and identifies IAM-relevant rules."""

    def __init__(self, rule_db_path: Optional[str] = None):
        """
        Initialize rule database reader.

        Args:
            rule_db_path: Path to services dir (e.g. engine_check/engine_check_aws/services)
                          or rule_db root (e.g. .../rule_db). Default: auto-detect.
        """
        if rule_db_path is None:
            base_path = Path(__file__).parent.parent.parent.parent
            for candidate in [
                base_path / "engine_check" / "engine_check_aws" / "services",
                base_path / "engine_input" / "engine_configscan_aws" / "input" / "rule_db" / "default" / "services",
            ]:
                if candidate.exists():
                    self._services_root = candidate
                    break
            else:
                self._services_root = base_path / "engine_check" / "engine_check_aws" / "services"
        else:
            p = Path(rule_db_path)
            if (p / "default" / "services").exists():
                self._services_root = p / "default" / "services"
            else:
                self._services_root = p
        self.rule_db_path = self._services_root

    def _metadata_dirs(self) -> List[Path]:
        """Yield (service_name, metadata_dir) for each service."""
        if not self._services_root.exists():
            return []
        out = []
        for d in self._services_root.iterdir():
            if not d.is_dir() or d.name.startswith("."):
                continue
            meta = d / "metadata"
            if meta.exists():
                out.append((d.name, meta))
        return out

    def get_metadata_path(self, service: str, rule_id: str) -> Path:
        """Path to metadata file for a rule."""
        return self._services_root / service / "metadata" / f"{rule_id}.yaml"

    def read_metadata(self, service: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """Read metadata for a rule."""
        path = self.get_metadata_path(service, rule_id)
        if not path.exists():
            return None
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Error reading {path}: {e}")
            return None

    def get_iam_security_info(self, service: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get IAM security context for a rule (applicable + modules)."""
        metadata = self.read_metadata(service, rule_id)
        if not metadata:
            return None
        domain = (metadata.get("domain") or "").strip().lower()
        if domain != IAM_DOMAIN:
            return None
        modules = _derive_iam_modules(rule_id, metadata)
        return {"applicable": True, "modules": modules}

    def is_iam_relevant(self, service: str, rule_id: str) -> bool:
        """True if rule is IAM-relevant (domain == identity_and_access_management)."""
        return self.get_iam_security_info(service, rule_id) is not None

    def get_rules_by_module(self, service: str, module: str) -> List[str]:
        """Rule IDs for a service that belong to an IAM module."""
        meta_dir = None
        for sname, mdir in self._metadata_dirs():
            if sname == service:
                meta_dir = mdir
                break
        if meta_dir is None or not meta_dir.exists():
            return []
        out = []
        for f in meta_dir.glob("*.yaml"):
            try:
                with open(f, "r") as fp:
                    meta = yaml.safe_load(fp)
                if (meta.get("domain") or "").strip().lower() != IAM_DOMAIN:
                    continue
                info = self.get_iam_security_info(service, meta.get("rule_id", ""))
                if info and module in info.get("modules", []):
                    out.append(meta.get("rule_id"))
            except Exception:
                continue
        return sorted(out)

    def list_services(self) -> List[str]:
        """List service names that have metadata."""
        return sorted([s for s, _ in self._metadata_dirs()])

    def get_all_iam_security_rules(self, service: str) -> Dict[str, Dict[str, Any]]:
        """rule_id -> iam_security info for a service."""
        result = {}
        for sname, meta_dir in self._metadata_dirs():
            if sname != service:
                continue
            for f in meta_dir.glob("*.yaml"):
                try:
                    with open(f, "r") as fp:
                        meta = yaml.safe_load(fp)
                except Exception:
                    continue
                rid = meta.get("rule_id")
                if not rid:
                    continue
                info = self.get_iam_security_info(service, rid)
                if info:
                    result[rid] = info
            break
        return result

    def get_all_iam_security_rule_ids(self, services: Optional[List[str]] = None) -> Set[str]:
        """Set of all IAM-relevant rule IDs (domain == identity_and_access_management)."""
        if services is None:
            services = self.list_services()
        rule_ids = set()
        for s in services:
            rule_ids.update(self.get_all_iam_security_rules(s).keys())
        logger.info(f"Found {len(rule_ids)} IAM security rule IDs across {len(services)} services")
        return rule_ids
