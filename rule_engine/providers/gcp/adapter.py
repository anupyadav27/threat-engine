"""
GCP (Google Cloud Platform) Provider Adapter Implementation
"""

from pathlib import Path
from ..plugin_base import CSPProvider


class GCPProvider(CSPProvider):
    """GCP (Google Cloud Platform) provider adapter"""
    
    @property
    def provider_name(self) -> str:
        return "gcp"
    
    @property
    def display_name(self) -> str:
        return "Google Cloud Platform"
    
    def get_sdk_module_pattern(self) -> str:
        return "googleapiclient.discovery.build"
    
    def format_discovery_id(self, service: str, method: str) -> str:
        """Format: gcp.service.method"""
        return f"gcp.{service}.{method}"
    
    def format_rule_id_prefix(self) -> str:
        return "gcp."
    
    def get_dependencies_file_name(self) -> str:
        return "gcp_dependencies_with_python_names_fully_enriched.json"
    
    def get_database_path(self, base_path: Path) -> Path:
        """Path: pythonsdk-database/gcp"""
        return base_path / "gcp"
    
    def get_output_path(self, base_path: Path, service: str) -> Path:
        """Path: gcp_compliance_python_engine/services/{service}/rules"""
        return base_path / "gcp_compliance_python_engine" / "services" / service / "rules"
    
    def get_metadata_path(self, base_path: Path, service: str) -> Path:
        """Path: gcp_compliance_python_engine/services/{service}/metadata"""
        return base_path / "gcp_compliance_python_engine" / "services" / service / "metadata"
    
    def validate_rule_id(self, rule_id: str) -> bool:
        """Validate rule ID starts with 'gcp.' and has at least 4 parts"""
        parts = rule_id.split(".")
        return len(parts) >= 4 and rule_id.startswith("gcp.")
    
    def get_documentation_url(self, service: str) -> str:
        """Generate GCP documentation URL"""
        # GCP docs typically use service names like 'compute', 'storage', etc.
        service_clean = service.replace('_', '-').lower()
        return f"https://cloud.google.com/{service_clean}/docs"

