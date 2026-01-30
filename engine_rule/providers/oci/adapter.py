"""
OCI (Oracle Cloud Infrastructure) Provider Adapter Implementation
"""

from pathlib import Path
from ..plugin_base import CSPProvider


class OCIProvider(CSPProvider):
    """OCI (Oracle Cloud Infrastructure) provider adapter"""
    
    @property
    def provider_name(self) -> str:
        return "oci"
    
    @property
    def display_name(self) -> str:
        return "Oracle Cloud Infrastructure"
    
    def get_sdk_module_pattern(self) -> str:
        return "oci.{service}.{Service}Client"
    
    def format_discovery_id(self, service: str, method: str) -> str:
        """Format: oci.service.method"""
        return f"oci.{service}.{method}"
    
    def format_rule_id_prefix(self) -> str:
        return "oci."
    
    def get_dependencies_file_name(self) -> str:
        return "oci_dependencies_with_python_names_fully_enriched.json"
    
    def get_database_path(self, base_path: Path) -> Path:
        """Path: pythonsdk-database/oci"""
        return base_path / "oci"
    
    def get_output_path(self, base_path: Path, service: str) -> Path:
        """Path: oci_compliance_python_engine/services/{service}/rules"""
        return base_path / "oci_compliance_python_engine" / "services" / service / "rules"
    
    def get_metadata_path(self, base_path: Path, service: str) -> Path:
        """Path: oci_compliance_python_engine/services/{service}/metadata"""
        return base_path / "oci_compliance_python_engine" / "services" / service / "metadata"
    
    def validate_rule_id(self, rule_id: str) -> bool:
        """Validate rule ID starts with 'oci.' and has at least 4 parts"""
        parts = rule_id.split(".")
        return len(parts) >= 4 and rule_id.startswith("oci.")
    
    def get_documentation_url(self, service: str) -> str:
        """Generate OCI documentation URL"""
        # OCI docs use service names like 'core', 'identity', etc.
        service_clean = service.replace('_', '-').lower()
        return f"https://docs.oracle.com/en-us/iaas/api/#/en/{service_clean}/latest/"

