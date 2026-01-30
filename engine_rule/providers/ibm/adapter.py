"""
IBM Cloud Provider Adapter Implementation
"""

from pathlib import Path
from ..plugin_base import CSPProvider


class IBMProvider(CSPProvider):
    """IBM Cloud provider adapter"""
    
    @property
    def provider_name(self) -> str:
        return "ibm"
    
    @property
    def display_name(self) -> str:
        return "IBM Cloud"
    
    def get_sdk_module_pattern(self) -> str:
        return "ibm_cloud_sdk_core.authenticators.IAuthenticator"
    
    def format_discovery_id(self, service: str, method: str) -> str:
        """Format: ibm.service.method"""
        return f"ibm.{service}.{method}"
    
    def format_rule_id_prefix(self) -> str:
        return "ibm."
    
    def get_dependencies_file_name(self) -> str:
        return "ibm_dependencies_with_python_names_fully_enriched.json"
    
    def get_database_path(self, base_path: Path) -> Path:
        """Path: pythonsdk-database/ibm"""
        return base_path / "ibm"
    
    def get_output_path(self, base_path: Path, service: str) -> Path:
        """Path: ibm_compliance_python_engine/services/{service}/rules"""
        return base_path / "ibm_compliance_python_engine" / "services" / service / "rules"
    
    def get_metadata_path(self, base_path: Path, service: str) -> Path:
        """Path: ibm_compliance_python_engine/services/{service}/metadata"""
        return base_path / "ibm_compliance_python_engine" / "services" / service / "metadata"
    
    def validate_rule_id(self, rule_id: str) -> bool:
        """Validate rule ID starts with 'ibm.' and has at least 4 parts"""
        parts = rule_id.split(".")
        return len(parts) >= 4 and rule_id.startswith("ibm.")
    
    def get_documentation_url(self, service: str) -> str:
        """Generate IBM Cloud documentation URL"""
        # IBM Cloud docs use service names like 'iam', 'vpc', etc.
        service_clean = service.replace('_', '-').lower()
        return f"https://cloud.ibm.com/docs/{service_clean}"

