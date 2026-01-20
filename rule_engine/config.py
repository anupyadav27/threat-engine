"""
Configuration management for YAML Rule Builder
"""

from pathlib import Path
from typing import Optional, Dict
import os

try:
    from .providers.plugin_base import CSPProvider
    from .providers.aws.adapter import AWSProvider
    from .providers.azure.adapter import AzureProvider
    from .providers.gcp.adapter import GCPProvider
    from .providers.oci.adapter import OCIProvider
    from .providers.alicloud.adapter import AliCloudProvider
    from .providers.ibm.adapter import IBMProvider
    from .providers.k8s.adapter import K8sProvider
except ImportError:
    from providers.plugin_base import CSPProvider
    from providers.aws.adapter import AWSProvider
    from providers.azure.adapter import AzureProvider
    from providers.gcp.adapter import GCPProvider
    from providers.oci.adapter import OCIProvider
    from providers.alicloud.adapter import AliCloudProvider
    from providers.ibm.adapter import IBMProvider
    from providers.k8s.adapter import K8sProvider


class Config:
    """Configuration settings with multi-provider support"""
    
    # Provider registry - all CSPs registered
    _provider_registry: Dict[str, type] = {
        "aws": AWSProvider,
        "azure": AzureProvider,
        "gcp": GCPProvider,
        "oci": OCIProvider,
        "alicloud": AliCloudProvider,
        "ibm": IBMProvider,
        "k8s": K8sProvider,
    }
    
    def __init__(self, provider: Optional[str] = None, pythonsdk_base: Optional[Path] = None):
        """
        Initialize configuration
        
        Args:
            provider: Optional provider name (defaults to None for backward compat)
            pythonsdk_base: Optional base path for SDK databases
        """
        self.project_root = Path(__file__).parent.parent
        self.default_provider = provider or "aws"  # Default for backward compatibility
        
        # Optional OUTPUT_DIR override (used in Kubernetes with /output + S3 sync sidecar)
        # If set, rule YAML + metadata will be written under:
        # - {OUTPUT_DIR}/{service}/{service}.yaml
        # - {OUTPUT_DIR}/{service}/metadata/{rule_id}.yaml
        # Default to engines-output/rule-engine/output for local development
        output_dir = os.environ.get("OUTPUT_DIR")
        if not output_dir:
            # Default to engines-output/rule-engine/output
            default_output = self.project_root.parent / "engines-output" / "rule-engine" / "output"
            if default_output.exists() or os.environ.get("WORKSPACE_ROOT"):
                workspace_root = Path(os.environ.get("WORKSPACE_ROOT", self.project_root.parent))
                output_dir = str(workspace_root / "engines-output" / "rule-engine" / "output")
        self.output_dir: Optional[Path] = Path(output_dir) if output_dir else None
        
        # Base paths (provider-agnostic)
        if pythonsdk_base:
            self.pythonsdk_base = pythonsdk_base
        else:
            self.pythonsdk_base = self.project_root / "pythonsdk-database"
        
        # Cache for provider adapters
        self._provider_cache: Dict[str, CSPProvider] = {}
        
        # Validate base path exists
        if not self.pythonsdk_base.exists():
            raise FileNotFoundError(f"PythonSDK base directory not found: {self.pythonsdk_base}")
    
    def get_provider_adapter(self, provider: str) -> CSPProvider:
        """
        Get provider adapter for specified provider
        
        Args:
            provider: Provider name (e.g., 'aws', 'azure', 'gcp')
            
        Returns:
            CSPProvider instance
            
        Raises:
            ValueError: If provider is not supported
        """
        if not provider:
            raise ValueError("provider is required")
        
        # Check cache first
        if provider in self._provider_cache:
            return self._provider_cache[provider]
        
        # Load provider adapter
        if provider not in self._provider_registry:
            raise ValueError(
                f"Provider '{provider}' is not supported. "
                f"Available providers: {list(self._provider_registry.keys())}"
            )
        
        adapter_class = self._provider_registry[provider]
        adapter = adapter_class()
        self._provider_cache[provider] = adapter
        return adapter
    
    def register_provider(self, provider_name: str, adapter_class: type):
        """Register a new provider adapter"""
        if not issubclass(adapter_class, CSPProvider):
            raise TypeError(f"Adapter class must inherit from CSPProvider")
        self._provider_registry[provider_name] = adapter_class
    
    def get_service_path(self, service_name: str, provider: str) -> Path:
        """Get path to service directory for provider"""
        adapter = self.get_provider_adapter(provider)
        database_path = adapter.get_database_path(self.pythonsdk_base)
        return database_path / service_name
    
    def get_output_path(self, service_name: str, provider: str) -> Path:
        """Get output path for generated YAML for provider"""
        if self.output_dir:
            return self.output_dir / service_name
        adapter = self.get_provider_adapter(provider)
        return adapter.get_output_path(self.project_root, service_name)
    
    def get_database_path(self, provider: str) -> Path:
        """Get database path for provider"""
        adapter = self.get_provider_adapter(provider)
        return adapter.get_database_path(self.pythonsdk_base)
    
    def get_metadata_path(self, service_name: str, provider: str) -> Path:
        """Get metadata path for provider"""
        if self.output_dir:
            return self.output_dir / service_name / "metadata"
        adapter = self.get_provider_adapter(provider)
        return adapter.get_metadata_path(self.project_root, service_name)
    
    def validate_service(self, service_name: str, provider: str, strict: bool = False) -> bool:
        """
        Check if service exists for provider with capability detection
        
        Args:
            service_name: Service name
            provider: Provider name
            strict: If True, requires all files. If False, only requires dependencies file.
            
        Returns:
            True if service is available (strict=False) or fully ready (strict=True)
        """
        try:
            service_path = self.get_service_path(service_name, provider)
            adapter = self.get_provider_adapter(provider)
        except (ValueError, FileNotFoundError):
            return False
        
        if not service_path.exists():
            # Check if consolidated dependencies file exists at CSP root
            csp_root = service_path.parent
            dependencies_file_name = adapter.get_dependencies_file_name()
            consolidated_deps = csp_root / dependencies_file_name
            if consolidated_deps.exists():
                # Service might be in consolidated file - check if it's loadable
                try:
                    import json
                    with open(consolidated_deps, 'r', encoding='utf-8') as f:
                        all_deps = json.load(f)
                        if isinstance(all_deps, dict):
                            # Check if service exists in consolidated file (case-insensitive)
                            service_lower = service_name.lower()
                            if any(key.lower() == service_lower for key in all_deps.keys()):
                                # Service exists in consolidated file
                                if strict:
                                    # For strict mode, still need service directory with other files
                                    return False
                                return True
                except Exception:
                    pass
            return False
        
        dependencies_file_name = adapter.get_dependencies_file_name()
        deps_path = service_path / dependencies_file_name
        
        # Dependencies file is required (check service or consolidated)
        has_deps = deps_path.exists()
        if not has_deps:
            csp_root = service_path.parent
            consolidated_deps = csp_root / dependencies_file_name
            has_deps = consolidated_deps.exists()
        
        if not has_deps:
            return False
        
        if strict:
            # Strict mode: require all files
            required_files = [
                "direct_vars.json",
                "dependency_index.json",
                dependencies_file_name
            ]
            return all((service_path / f).exists() for f in required_files)
        else:
            # Relaxed mode: only require dependencies (can work with empty structures)
            return True
    
    # Backward compatibility methods (default to AWS)
    def _get_default_output_path(self, service_name: str) -> Path:
        """Backward compatibility: get AWS output path"""
        return self.get_output_path(service_name, "aws")
    
    def _get_default_service_path(self, service_name: str) -> Path:
        """Backward compatibility: get AWS service path"""
        return self.get_service_path(service_name, "aws")

