"""
AliCloud (Alibaba Cloud) Provider Adapter Implementation
"""

from pathlib import Path
from ..plugin_base import CSPProvider


class AliCloudProvider(CSPProvider):
    """AliCloud (Alibaba Cloud) provider adapter"""
    
    @property
    def provider_name(self) -> str:
        return "alicloud"
    
    @property
    def display_name(self) -> str:
        return "Alibaba Cloud (AliCloud)"
    
    def get_sdk_module_pattern(self) -> str:
        return "aliyunsdkcore.client.AcsClient"
    
    def format_discovery_id(self, service: str, method: str) -> str:
        """Format: alicloud.service.method"""
        return f"alicloud.{service}.{method}"
    
    def format_rule_id_prefix(self) -> str:
        return "alicloud."
    
    def get_dependencies_file_name(self) -> str:
        return "alicloud_dependencies_with_python_names_fully_enriched.json"
    
    def get_database_path(self, base_path: Path) -> Path:
        """Path: pythonsdk-database/alicloud"""
        return base_path / "alicloud"
    
    def get_output_path(self, base_path: Path, service: str) -> Path:
        """Path: alicloud_compliance_python_engine/services/{service}/rules"""
        return base_path / "alicloud_compliance_python_engine" / "services" / service / "rules"
    
    def get_metadata_path(self, base_path: Path, service: str) -> Path:
        """Path: alicloud_compliance_python_engine/services/{service}/metadata"""
        return base_path / "alicloud_compliance_python_engine" / "services" / service / "metadata"
    
    def validate_rule_id(self, rule_id: str) -> bool:
        """Validate rule ID starts with 'alicloud.' and has at least 4 parts"""
        parts = rule_id.split(".")
        return len(parts) >= 4 and rule_id.startswith("alicloud.")
    
    def get_documentation_url(self, service: str) -> str:
        """Generate AliCloud documentation URL"""
        # AliCloud docs use service names like 'ecs', 'vpc', etc.
        service_clean = service.replace('_', '-').lower()
        return f"https://www.alibabacloud.com/help/en/{service_clean}"

