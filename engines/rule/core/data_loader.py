"""
Data loader for JSON files
"""

import json
from pathlib import Path
from typing import Dict, Optional
try:
    from ..config import Config
except ImportError:
    from config import Config

class DataLoader:
    """Loads and caches JSON data files with provider awareness"""
    
    def __init__(self, config: Config):
        self.config = config
        self._cache: Dict[str, Dict] = {}  # Key: f"{provider}:{service_name}"
    
    def load_service_data(self, service_name: str, provider: str) -> Dict:
        """
        Load all required JSON files for a service in a specific provider
        
        Args:
            service_name: Service name (e.g., 'iam', 's3')
            provider: Provider name (e.g., 'aws', 'azure')
            
        Returns:
            Dictionary with direct_vars, dependency_index, and provider-specific dependencies
            
        Raises:
            FileNotFoundError: If service directory or critical files are missing
            ValueError: If service not found in dependencies
        """
        cache_key = f"{provider}:{service_name}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Get provider adapter
        provider_adapter = self.config.get_provider_adapter(provider)
        
        # Get provider-specific paths
        service_path = self.config.get_service_path(service_name, provider)
        
        if not service_path.exists():
            raise FileNotFoundError(
                f"Service directory not found for {provider}/{service_name}: {service_path}"
            )
        
        # Load files with provider-specific naming (gracefully handle missing files)
        dependencies_file_name = provider_adapter.get_dependencies_file_name()
        
        # Try to load each file, providing empty dict if missing (for incomplete providers)
        data = {}
        
        # Load direct_vars.json (may be missing for some CSPs)
        direct_vars_path = service_path / "direct_vars.json"
        if direct_vars_path.exists():
            data["direct_vars"] = self._load_json(direct_vars_path)
        else:
            # Graceful degradation: create empty structure
            data["direct_vars"] = {"fields": {}}
        
        # Load dependency_index.json (may be missing for some CSPs)
        dependency_index_path = service_path / "dependency_index.json"
        if dependency_index_path.exists():
            data["dependency_index"] = self._load_json(dependency_index_path)
        else:
            # Graceful degradation: create empty structure
            data["dependency_index"] = {"entity_paths": {}, "roots": []}
        
        # Load provider dependencies file (should exist, but handle gracefully)
        deps_path = service_path / dependencies_file_name
        if deps_path.exists():
            data["provider_deps"] = self._load_json(deps_path)
        else:
            # Check for consolidated file at CSP root level
            csp_root = service_path.parent
            consolidated_deps = csp_root / dependencies_file_name
            if consolidated_deps.exists():
                all_deps = self._load_json(consolidated_deps)
                # Extract service-specific data if it's in consolidated format
                if isinstance(all_deps, dict) and service_name in all_deps:
                    data["provider_deps"] = {service_name: all_deps[service_name]}
                else:
                    data["provider_deps"] = all_deps
            else:
                raise FileNotFoundError(
                    f"Dependencies file not found for {provider}/{service_name}. "
                    f"Expected: {deps_path} or {consolidated_deps}"
                )
        
        # Use generic key for backward compatibility (boto3_deps, azure_deps, etc.)
        # This allows existing code to work
        if provider == "aws":
            data["boto3_deps"] = data["provider_deps"]
        else:
            data["boto3_deps"] = data["provider_deps"]  # Generic key for compatibility
        
        # Validate service exists in dependencies
        # The dependencies file structure is: {service_name: {service: "...", independent: [...], ...}}
        provider_deps = data.get("provider_deps") or data.get("boto3_deps", {})
        
        if isinstance(provider_deps, dict):
            # Check if service_name exists as a top-level key
            service_key = service_name
            if service_key not in provider_deps:
                # Try to find the key (case-insensitive or alternative naming)
                for key in provider_deps.keys():
                    if isinstance(key, str) and key.lower() == service_name.lower():
                        service_key = key
                        break
            
            # Validate service exists (but don't fail if dependencies file is consolidated format)
            if service_key not in provider_deps:
                # Check if it's a consolidated file (single service entry)
                if len(provider_deps) == 1:
                    # Use the only key as service_key
                    service_key = list(provider_deps.keys())[0]
                    data["provider_deps"] = {service_key: provider_deps[service_key]}
                else:
                    available = list(provider_deps.keys())[:10]
                    raise ValueError(
                        f"Service '{service_name}' not found in {provider} dependencies. "
                        f"Available services: {available}"
                    )
        
        self._cache[cache_key] = data
        return data
    
    def _load_json(self, file_path: Path) -> Dict:
        """Load JSON file with error handling"""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in file {file_path}: {e}")
        except Exception as e:
            raise IOError(f"Error reading file {file_path}: {e}")
    
    def check_provider_capability(self, provider: str, service_name: str) -> Dict[str, bool]:
        """
        Check which files exist for a provider/service (capability detection)
        
        Returns:
            Dictionary with file existence flags:
            {
                "has_dependencies": bool,
                "has_dependency_index": bool,
                "has_direct_vars": bool,
                "is_ready": bool  # All required files present
            }
        """
        try:
            provider_adapter = self.config.get_provider_adapter(provider)
            service_path = self.config.get_service_path(service_name, provider)
        except (ValueError, FileNotFoundError):
            return {
                "has_dependencies": False,
                "has_dependency_index": False,
                "has_direct_vars": False,
                "is_ready": False
            }
        
        if not service_path.exists():
            return {
                "has_dependencies": False,
                "has_dependency_index": False,
                "has_direct_vars": False,
                "is_ready": False
            }
        
        dependencies_file_name = provider_adapter.get_dependencies_file_name()
        
        # Check individual service file
        deps_path = service_path / dependencies_file_name
        if not deps_path.exists():
            # Check consolidated file
            csp_root = service_path.parent
            consolidated_deps = csp_root / dependencies_file_name
            has_dependencies = consolidated_deps.exists()
        else:
            has_dependencies = True
        
        has_dependency_index = (service_path / "dependency_index.json").exists()
        has_direct_vars = (service_path / "direct_vars.json").exists()
        
        # Service is ready if it has dependencies (required) and at least one of the others
        is_ready = has_dependencies and (has_dependency_index or has_direct_vars)
        
        return {
            "has_dependencies": has_dependencies,
            "has_dependency_index": has_dependency_index,
            "has_direct_vars": has_direct_vars,
            "is_ready": is_ready
        }
    
    def clear_cache(self):
        """Clear the cache"""
        self._cache.clear()

