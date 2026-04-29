"""
Configuration Parser for DAST Scanner
Handles multi-source configuration loading and merging
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import re


class ConfigurationError(Exception):
    """Configuration-related errors"""
    pass


# Built-in scan profiles — applied before CLI flags so flags always win
PROFILES: Dict[str, Dict[str, Any]] = {
    'quick': {
        'scan': {
            'intensity': 'quick',
            'performance': {'rate_limit': 20},
            'crawler': {'max_depth': 2, 'max_pages': 100},
        }
    },
    'normal': {
        'scan': {
            'intensity': 'normal',
            'performance': {'rate_limit': 50},
            'crawler': {'max_depth': 5, 'max_pages': 1000},
        }
    },
    'deep': {
        'scan': {
            'intensity': 'thorough',
            'performance': {'rate_limit': 100},
            'crawler': {'max_depth': 10, 'max_pages': 5000},
        }
    },
}


class TargetConfig:
    """
    Target configuration management
    Handles loading, validation, and merging of configurations
    """
    
    def __init__(self, config_file: Optional[str] = None,
                 profile: Optional[str] = None):
        """
        Initialize configuration

        Priority (highest → lowest): CLI flags > env vars > YAML file > profile > defaults

        Profile is applied first so that explicit values in the YAML config file
        always override the profile.  CLI flags are applied last via update_from_cli().

        Args:
            config_file: Path to YAML/JSON config file
            profile: Named scan profile ('quick', 'normal', 'deep')
        """
        self.config = self._load_default_config()

        # Apply named profile as base — overridden by file, env, and CLI
        if profile and profile in PROFILES:
            self.config = self._merge_configs(self.config, PROFILES[profile])

        # Load from file — explicit YAML values win over profile
        if config_file:
            file_config = self._load_config_file(config_file)
            self.config = self._merge_configs(self.config, file_config)

        # Override with environment variables (higher priority than file)
        env_config = self._load_env_config()
        self.config = self._merge_configs(self.config, env_config)
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load built-in safe defaults"""
        return {
            'target': {
                'url': None,
                'base_path': '/',
                'scope': {
                    'include': ['/*'],
                    'exclude': []
                },
                'allowed_domains': [],
                'blocked_extensions': [
                    '.pdf', '.zip', '.tar', '.gz', '.mp4', 
                    '.avi', '.jpg', '.jpeg', '.png', '.gif'
                ]
            },
            'authentication': {
                'type': 'none',
                'session': {
                    'maintain_session': True,
                    'session_timeout': 3600,
                    'verify_endpoint': None
                }
            },
            'scan': {
                'intensity': 'normal',
                'performance': {
                    'threads': 10,
                    'rate_limit': 50,
                    'request_timeout': 30,
                    'max_redirects': 5,
                    'retry_attempts': 3
                },
                'crawler': {
                    'max_depth': 5,
                    'max_pages': 1000,
                    'follow_redirects': True,
                    'respect_robots_txt': False,
                    'user_agent': 'DAST-Scanner/1.0'
                }
            },
            'safety': {
                'environment': 'staging',
                'require_authorization': False,
                'max_scan_duration': 7200,
                'authorization_file': '/.well-known/security.txt'
            },
            'output': {
                'reports_dir': './reports',
                'format': ['json', 'html'],
                'log_level': 'INFO'
            }
        }
    
    def _load_config_file(self, config_file: str) -> Dict[str, Any]:
        """
        Load configuration from YAML or JSON file
        
        Args:
            config_file: Path to config file
        
        Returns:
            Configuration dictionary
        """
        path = Path(config_file)

        # If not found as-is, search the config/ directory alongside the CWD
        if not path.exists():
            candidate = Path('config') / path.name
            if candidate.exists():
                path = candidate
            else:
                raise ConfigurationError(f"Config file not found: {config_file}")
        
        with open(path, 'r') as f:
            if path.suffix in ['.yaml', '.yml']:
                config = yaml.safe_load(f) or {}
                # Expand environment variables in YAML
                return self._expand_env_vars(config)
            elif path.suffix == '.json':
                return json.load(f)
            else:
                raise ConfigurationError(
                    f"Unsupported config format: {path.suffix}. Use .yaml, .yml, or .json"
                )
    
    def _expand_env_vars(self, config: Any) -> Any:
        """Recursively expand environment variables in config"""
        if isinstance(config, dict):
            return {k: self._expand_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [self._expand_env_vars(item) for item in config]
        elif isinstance(config, str):
            # Replace ${VAR_NAME} with environment variable value
            pattern = r'\$\{([^}]+)\}'
            matches = re.findall(pattern, config)
            for var_name in matches:
                env_value = os.getenv(var_name, '')
                config = config.replace(f'${{{var_name}}}', env_value)
            return config
        else:
            return config
    
    def _load_env_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        env_config = {}
        
        # Map environment variables to config paths
        env_mappings = {
            'DAST_TARGET_URL': 'target.url',
            'DAST_AUTH_TYPE': 'authentication.type',
            'DAST_AUTH_TOKEN': 'authentication.bearer.token',
            'DAST_USERNAME': 'authentication.basic.username',
            'DAST_PASSWORD': 'authentication.basic.password',
            'DAST_ENVIRONMENT': 'safety.environment',
            'DAST_RATE_LIMIT': 'scan.performance.rate_limit',
            'DAST_MAX_DEPTH': 'scan.crawler.max_depth',
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                # Try to convert to appropriate type
                if value.isdigit():
                    value = int(value)
                self._set_nested_value(env_config, config_path, value)
        
        return env_config
    
    def _merge_configs(self, base: Dict, override: Dict) -> Dict:
        """
        Deep merge two configuration dictionaries
        override takes precedence over base
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _set_nested_value(self, config: Dict, path: str, value: Any):
        """Set nested dictionary value using dot notation"""
        keys = path.split('.')
        current = config
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def get(self, path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            path: Dot-separated path (e.g., 'target.url')
            default: Default value if not found
        
        Returns:
            Configuration value
        """
        keys = path.split('.')
        current = self.config
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        
        return current
    
    def set(self, path: str, value: Any):
        """Set configuration value using dot notation"""
        self._set_nested_value(self.config, path, value)
    
    def update_from_cli(self, cli_args: Dict[str, Any]):
        """
        Update configuration from CLI arguments
        
        Args:
            cli_args: Dictionary of CLI arguments
        """
        cli_mappings = {
            'url': 'target.url',
            'scope': 'target.scope.include',
            'exclude': 'target.scope.exclude',
            'auth_type': 'authentication.type',
            'auth_token': 'authentication.bearer.token',
            'auth_header': 'authentication.custom_header',
            'username': 'authentication.basic.username',
            'password': 'authentication.basic.password',
            'cookie': 'authentication.cookie.cookie_value',
            'intensity': 'scan.intensity',
            'rate_limit': 'scan.performance.rate_limit',
            'threads': 'scan.performance.threads',
            'max_depth': 'scan.crawler.max_depth',
            'max_pages': 'scan.crawler.max_pages',
            'environment': 'safety.environment',
            'output': 'output.reports_dir',
            'formats': 'output.format',
            'fail_on': 'output.fail_on',
        }
        
        for cli_arg, config_path in cli_mappings.items():
            if cli_arg in cli_args and cli_args[cli_arg] is not None:
                self.set(config_path, cli_args[cli_arg])
    
    def to_dict(self) -> Dict[str, Any]:
        """Get full configuration as dictionary"""
        return self.config.copy()
    
