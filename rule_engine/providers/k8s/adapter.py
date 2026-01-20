"""
Kubernetes (K8s) Provider Adapter Implementation
"""

from pathlib import Path
from ..plugin_base import CSPProvider


class K8sProvider(CSPProvider):
    """Kubernetes (K8s) provider adapter"""
    
    @property
    def provider_name(self) -> str:
        return "k8s"
    
    @property
    def display_name(self) -> str:
        return "Kubernetes (K8s)"
    
    def get_sdk_module_pattern(self) -> str:
        return "kubernetes.client.{ApiClass}"
    
    def format_discovery_id(self, service: str, method: str) -> str:
        """Format: k8s.service.method"""
        return f"k8s.{service}.{method}"
    
    def format_rule_id_prefix(self) -> str:
        return "k8s."
    
    def get_dependencies_file_name(self) -> str:
        return "k8s_dependencies_with_python_names_fully_enriched.json"
    
    def get_database_path(self, base_path: Path) -> Path:
        """Path: pythonsdk-database/k8s"""
        return base_path / "k8s"
    
    def get_output_path(self, base_path: Path, service: str) -> Path:
        """Path: k8s_compliance_python_engine/services/{service}/rules"""
        return base_path / "k8s_compliance_python_engine" / "services" / service / "rules"
    
    def get_metadata_path(self, base_path: Path, service: str) -> Path:
        """Path: k8s_compliance_python_engine/services/{service}/metadata"""
        return base_path / "k8s_compliance_python_engine" / "services" / service / "metadata"
    
    def validate_rule_id(self, rule_id: str) -> bool:
        """Validate rule ID starts with 'k8s.' and has at least 4 parts"""
        parts = rule_id.split(".")
        return len(parts) >= 4 and rule_id.startswith("k8s.")
    
    def get_documentation_url(self, service: str) -> str:
        """Generate Kubernetes documentation URL"""
        # K8s docs use resource types like 'pod', 'deployment', etc.
        service_clean = service.replace('_', '-').lower()
        return f"https://kubernetes.io/docs/concepts/workloads/{service_clean}/"

