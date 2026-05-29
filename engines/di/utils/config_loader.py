"""
Discovery Configuration Loader
==============================
Database-driven configuration loader for discovery services.

Replaces:
- discovery_helper.py (boto3 client name mappings)
- discovery_resource_mapper.py (extraction patterns)
- Hardcoded scope detection (regional/global)

Usage:
    from engine_discoveries.utils.config_loader import DiscoveryConfigLoader

    config_loader = DiscoveryConfigLoader(provider='aws')
    boto3_name = config_loader.get_boto3_client_name('ec2')
    scope = config_loader.get_scope('iam')  # Returns 'global'
    filters = config_loader.get_filter_rules('kms')
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)


class DiscoveryConfigLoader:
    """Load service configuration from rule_discoveries table"""

    def __init__(self, provider: str = 'aws', db_config: Optional[Dict[str, Any]] = None):
        """
        Initialize config loader.

        Args:
            provider: Cloud provider (default: 'aws')
            db_config: Database connection config. If None, reads from env.
        """
        self.provider = provider
        self._cache = {}
        self._conn = None

        # Database configuration
        if db_config:
            self.db_config = db_config
        else:
            self.db_config = self._get_db_config_from_env()

    def _get_db_config_from_env(self) -> Dict[str, Any]:
        """Get database configuration from environment variables"""
        return {
            'host': os.getenv('CHECK_DB_HOST', 'localhost'),
            'port': int(os.getenv('CHECK_DB_PORT', '5432')),
            'database': os.getenv('CHECK_DB_NAME', 'threat_engine_check'),
            'user': os.getenv('CHECK_DB_USER', 'check_user'),
            'password': os.getenv('CHECK_DB_PASSWORD', 'check_password'),
        }

    def _get_connection(self):
        """Get database connection (lazy initialization with connection pooling)"""
        if self._conn is None or self._conn.closed:
            try:
                self._conn = psycopg2.connect(**self.db_config)
                logger.debug(f"Connected to database: {self.db_config['database']}")
            except Exception as e:
                logger.error(f"Database connection failed: {e}")
                raise

        return self._conn

    def _load_service_config(self, service: str) -> Dict[str, Any]:
        """
        Load full service config from database with caching.

        Args:
            service: Service name (e.g., 'ec2', 's3', 'iam')

        Returns:
            Dict containing service configuration:
            {
                'boto3_client_name': str,
                'scope': str ('regional' or 'global'),
                'filter_rules': dict,
                'pagination_config': dict,
                'extraction_patterns': dict,
                'arn_pattern': str
            }
        """
        # Check cache first
        cache_key = f"{self.provider}:{service}"
        if cache_key in self._cache:
            logger.debug(f"Cache hit for service: {service}")
            return self._cache[cache_key]

        # Query database
        try:
            conn = self._get_connection()
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            query = """
                SELECT
                    boto3_client_name,
                    arn_identifier,
                    arn_identifier_independent_methods,
                    arn_identifier_dependent_methods,
                    filter_rules
                FROM rule_discoveries
                WHERE service = %s AND provider = %s AND is_active = TRUE
                LIMIT 1
            """

            cursor.execute(query, (service, self.provider))
            row = cursor.fetchone()
            cursor.close()

            if row:
                # Convert to dict and handle None values
                config = dict(row)

                # Ensure default values for missing fields
                config.setdefault('boto3_client_name', service)
                config.setdefault('scope', 'regional')
                config.setdefault('filter_rules', {'api_filters': [], 'response_filters': []})
                config.setdefault('pagination_config', self._default_pagination_config())
                config.setdefault('extraction_patterns', {})
                config.setdefault('arn_pattern', None)

                # Cache the result
                self._cache[cache_key] = config
                logger.debug(f"Loaded config for service: {service} (scope={config['scope']})")

                return config
            else:
                # Service not found - return defaults
                logger.warning(f"Service '{service}' not found in database for provider '{self.provider}'. Using defaults.")
                default_config = {
                    'boto3_client_name': service,
                    'scope': 'regional',
                    'filter_rules': {'api_filters': [], 'response_filters': []},
                    'pagination_config': self._default_pagination_config(),
                    'extraction_patterns': {},
                    'arn_pattern': None
                }

                # Cache the default
                self._cache[cache_key] = default_config
                return default_config

        except Exception as e:
            logger.error(f"Error loading service config for '{service}': {e}")
            # Rollback to clear aborted transaction state
            try:
                if self._conn and not self._conn.closed:
                    self._conn.rollback()
            except Exception:
                self._conn = None  # Force reconnect next time
            # Return defaults on error
            return {
                'boto3_client_name': service,
                'scope': 'regional',
                'filter_rules': {'api_filters': [], 'response_filters': []},
                'pagination_config': self._default_pagination_config(),
                'extraction_patterns': {},
                'arn_pattern': None
            }

    def _default_pagination_config(self) -> Dict[str, Any]:
        """Get default pagination configuration"""
        return {
            'default_page_size': 1000,
            'max_pages': 100,
            'timeout_seconds': 600,
            'max_items': 100000,
            'token_field': 'NextToken',
            'result_array_field': None,
            'supports_native_pagination': True,
            'circular_token_detection': True
        }

    # ========================================================================
    # Public API Methods
    # ========================================================================

    def get_boto3_client_name(self, service: str) -> str:
        """
        Get boto3 client name for a service.

        Replaces: discovery_helper.get_boto3_client_name()

        Args:
            service: Service name (e.g., 'cognito', 'vpc')

        Returns:
            Boto3 client name (e.g., 'cognito-idp', 'ec2')

        Examples:
            >>> loader = DiscoveryConfigLoader()
            >>> loader.get_boto3_client_name('cognito')
            'cognito-idp'
            >>> loader.get_boto3_client_name('vpc')
            'ec2'
        """
        config = self._load_service_config(service)
        return config.get('boto3_client_name', service)

    def get_scope(self, service: str) -> str:
        """
        Get service scope (regional or global).

        Args:
            service: Service name (e.g., 'iam', 'ec2')

        Returns:
            'global' or 'regional'

        Examples:
            >>> loader = DiscoveryConfigLoader()
            >>> loader.get_scope('iam')
            'global'
            >>> loader.get_scope('ec2')
            'regional'
        """
        config = self._load_service_config(service)
        return config.get('scope', 'regional')

    def get_filter_rules(self, service: str) -> Dict[str, list]:
        """
        Get filter rules for a service.

        Args:
            service: Service name

        Returns:
            Dict with 'api_filters' and 'response_filters' lists

        Example:
            >>> loader = DiscoveryConfigLoader()
            >>> rules = loader.get_filter_rules('kms')
            >>> rules['response_filters']
            [{'discovery_id': 'aws.kms.list_aliases', 'pattern': '^alias/aws/', ...}]
        """
        config = self._load_service_config(service)
        filter_rules = config.get('filter_rules', {})

        # Ensure structure
        if not isinstance(filter_rules, dict):
            filter_rules = {'api_filters': [], 'response_filters': []}

        filter_rules.setdefault('api_filters', [])
        filter_rules.setdefault('response_filters', [])

        return filter_rules

    def get_pagination_config(self, service: str) -> Dict[str, Any]:
        """
        Get pagination configuration for a service.

        Args:
            service: Service name

        Returns:
            Dict with pagination settings

        Example:
            >>> loader = DiscoveryConfigLoader()
            >>> config = loader.get_pagination_config('sagemaker')
            >>> config['default_page_size']
            100
        """
        config = self._load_service_config(service)
        pagination_config = config.get('pagination_config', {})

        # Merge with defaults
        if not isinstance(pagination_config, dict):
            pagination_config = {}

        default_config = self._default_pagination_config()
        default_config.update(pagination_config)

        return default_config

    def get_extraction_patterns(self, service: str) -> Dict[str, Dict]:
        """
        Get ARN/ID extraction patterns for a service.

        Replaces: discovery_resource_mapper.load_service_config()

        Args:
            service: Service name

        Returns:
            Dict mapping resource types to extraction patterns:
            {
                'bucket': {
                    'arn_fields': ['BucketArn', 'Arn'],
                    'id_fields': ['Name', 'BucketName'],
                    'name_fields': ['Name']
                }
            }

        Example:
            >>> loader = DiscoveryConfigLoader()
            >>> patterns = loader.get_extraction_patterns('s3')
            >>> patterns['bucket']['id_fields']
            ['Name', 'BucketName']
        """
        config = self._load_service_config(service)
        return config.get('extraction_patterns', {})

    def get_arn_pattern(self, service: str) -> Optional[str]:
        """
        Get ARN pattern template for a service.

        Args:
            service: Service name

        Returns:
            ARN pattern string or None

        Example:
            >>> loader = DiscoveryConfigLoader()
            >>> loader.get_arn_pattern('ec2')
            'arn:aws:ec2:{region}:{account_id}:{resource_type}/{resource_id}'
        """
        config = self._load_service_config(service)
        return config.get('arn_pattern')

    def clear_cache(self, service: Optional[str] = None):
        """
        Clear cached configuration.

        Args:
            service: If provided, clear only this service. Otherwise clear all.
        """
        if service:
            cache_key = f"{self.provider}:{service}"
            if cache_key in self._cache:
                del self._cache[cache_key]
                logger.debug(f"Cleared cache for service: {service}")
        else:
            self._cache.clear()
            logger.debug("Cleared entire cache")

    def close(self):
        """Close database connection"""
        if self._conn and not self._conn.closed:
            self._conn.close()
            logger.debug("Closed database connection")

    def __del__(self):
        """Cleanup on deletion"""
        self.close()


# Singleton instance for convenience
_default_loader = None


def get_default_loader(provider: str = 'aws') -> DiscoveryConfigLoader:
    """
    Get the default singleton config loader instance.

    Args:
        provider: Cloud provider

    Returns:
        DiscoveryConfigLoader instance
    """
    global _default_loader
    if _default_loader is None:
        _default_loader = DiscoveryConfigLoader(provider=provider)
    return _default_loader
