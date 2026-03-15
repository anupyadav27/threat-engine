"""
Pagination Engine - Database-Driven Pagination
===============================================
Handle database-configured pagination for discovery operations.

Replaces:
- Hardcoded pagination logic in service_scanner.py (lines 1490-1500)
- Service-specific page size if/elif chains

Usage:
    from engine_discoveries.utils.config_loader import DiscoveryConfigLoader
    from engine_discoveries.utils.pagination_engine import PaginationEngine

    config_loader = DiscoveryConfigLoader(provider='aws')
    pagination_engine = PaginationEngine(config_loader)

    # Get page size for service
    page_size = pagination_engine.get_page_size('sagemaker')  # Returns 100

    # Get token field name
    token_field = pagination_engine.get_token_field('s3', 'list_buckets')  # Returns 'Marker'
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class PaginationEngine:
    """Handle database-driven pagination configuration"""

    def __init__(self, config_loader):
        """
        Initialize pagination engine.

        Args:
            config_loader: DiscoveryConfigLoader instance
        """
        self.config_loader = config_loader

    # ========================================================================
    # Page Size Configuration
    # ========================================================================

    def get_page_size(
        self,
        service: str,
        action: Optional[str] = None
    ) -> int:
        """
        Get page size for service/action.

        Replaces: Hardcoded if/elif chain for service-specific page sizes

        Args:
            service: Service name (e.g., 'sagemaker', 'ec2')
            action: Optional action name for action-specific overrides

        Returns:
            Page size (default: 1000)

        Examples:
            >>> pagination_engine.get_page_size('sagemaker')
            100
            >>> pagination_engine.get_page_size('cognito')
            60
            >>> pagination_engine.get_page_size('ec2')
            1000
        """
        try:
            pagination_config = self.config_loader.get_pagination_config(service)

            # Check for action-specific override first
            if action:
                service_overrides = pagination_config.get('service_overrides', {})
                if action in service_overrides:
                    override_config = service_overrides[action]
                    if 'default_page_size' in override_config:
                        page_size = override_config['default_page_size']
                        logger.debug(f"Using action-specific page size: {page_size} for {service}.{action}")
                        return page_size

            # Use service default
            page_size = pagination_config.get('default_page_size', 1000)
            logger.debug(f"Using page size: {page_size} for {service}")
            return page_size

        except Exception as e:
            logger.error(f"Error getting page size for {service}: {e}")
            return 1000  # Safe default

    def get_max_pages(self, service: str) -> int:
        """
        Get maximum pages limit for service.

        Args:
            service: Service name

        Returns:
            Max pages (default: 100)
        """
        try:
            pagination_config = self.config_loader.get_pagination_config(service)
            return pagination_config.get('max_pages', 100)
        except Exception as e:
            logger.error(f"Error getting max_pages for {service}: {e}")
            return 100

    def get_max_items(self, service: str) -> int:
        """
        Get maximum items limit for service.

        Args:
            service: Service name

        Returns:
            Max items (default: 100000)
        """
        try:
            pagination_config = self.config_loader.get_pagination_config(service)
            return pagination_config.get('max_items', 100000)
        except Exception as e:
            logger.error(f"Error getting max_items for {service}: {e}")
            return 100000

    def get_timeout_seconds(self, service: str) -> int:
        """
        Get pagination timeout for service.

        Args:
            service: Service name

        Returns:
            Timeout in seconds (default: 600)
        """
        try:
            pagination_config = self.config_loader.get_pagination_config(service)
            return pagination_config.get('timeout_seconds', 600)
        except Exception as e:
            logger.error(f"Error getting timeout for {service}: {e}")
            return 600

    # ========================================================================
    # Token Field Configuration
    # ========================================================================

    def get_token_field(
        self,
        service: str,
        action: Optional[str] = None
    ) -> str:
        """
        Get pagination token field name for service/action.

        Args:
            service: Service name (e.g., 's3', 'iam')
            action: Optional action name for action-specific overrides

        Returns:
            Token field name (default: 'NextToken')

        Examples:
            >>> pagination_engine.get_token_field('s3', 'list_buckets')
            'Marker'
            >>> pagination_engine.get_token_field('s3', 'list_objects_v2')
            'ContinuationToken'
            >>> pagination_engine.get_token_field('iam')
            'Marker'
            >>> pagination_engine.get_token_field('ec2')
            'NextToken'
        """
        try:
            pagination_config = self.config_loader.get_pagination_config(service)

            # Check for action-specific override first
            if action:
                service_overrides = pagination_config.get('service_overrides', {})
                if action in service_overrides:
                    override_config = service_overrides[action]
                    if 'token_field' in override_config:
                        token_field = override_config['token_field']
                        logger.debug(f"Using action-specific token field: {token_field} for {service}.{action}")
                        return token_field

            # Use service default
            token_field = pagination_config.get('token_field', 'NextToken')
            logger.debug(f"Using token field: {token_field} for {service}")
            return token_field

        except Exception as e:
            logger.error(f"Error getting token field for {service}: {e}")
            return 'NextToken'  # AWS default

    def get_result_array_field(
        self,
        service: str,
        action: Optional[str] = None
    ) -> Optional[str]:
        """
        Get result array field name for service/action.

        Args:
            service: Service name
            action: Optional action name

        Returns:
            Result array field name or None (None means auto-detect)

        Note:
            Most AWS APIs auto-detect the result array field.
            Azure uses 'value', GCP uses 'items' typically.
        """
        try:
            pagination_config = self.config_loader.get_pagination_config(service)

            # Check for action-specific override
            if action:
                service_overrides = pagination_config.get('service_overrides', {})
                if action in service_overrides:
                    override_config = service_overrides[action]
                    if 'result_array_field' in override_config:
                        return override_config['result_array_field']

            # Use service default
            return pagination_config.get('result_array_field')

        except Exception as e:
            logger.error(f"Error getting result_array_field for {service}: {e}")
            return None

    # ========================================================================
    # Pagination Behavior Configuration
    # ========================================================================

    def supports_native_pagination(self, service: str) -> bool:
        """
        Check if service supports native SDK pagination.

        Args:
            service: Service name

        Returns:
            True if native pagination is supported (default: True)
        """
        try:
            pagination_config = self.config_loader.get_pagination_config(service)
            return pagination_config.get('supports_native_pagination', True)
        except Exception:
            return True

    def has_circular_token_detection(self, service: str) -> bool:
        """
        Check if circular token detection is enabled.

        Args:
            service: Service name

        Returns:
            True if enabled (default: True)
        """
        try:
            pagination_config = self.config_loader.get_pagination_config(service)
            return pagination_config.get('circular_token_detection', True)
        except Exception:
            return True

    # ========================================================================
    # Full Pagination Configuration
    # ========================================================================

    def get_pagination_params(
        self,
        service: str,
        action: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get complete pagination parameters for service/action.

        Args:
            service: Service name
            action: Optional action name

        Returns:
            Dict with all pagination parameters:
            {
                'default_page_size': int,
                'max_pages': int,
                'max_items': int,
                'timeout_seconds': int,
                'token_field': str,
                'result_array_field': str or None,
                'supports_native_pagination': bool,
                'circular_token_detection': bool
            }

        Example:
            >>> params = pagination_engine.get_pagination_params('sagemaker')
            >>> params['default_page_size']
            100
            >>> params['token_field']
            'NextToken'
        """
        return {
            'default_page_size': self.get_page_size(service, action),
            'max_pages': self.get_max_pages(service),
            'max_items': self.get_max_items(service),
            'timeout_seconds': self.get_timeout_seconds(service),
            'token_field': self.get_token_field(service, action),
            'result_array_field': self.get_result_array_field(service, action),
            'supports_native_pagination': self.supports_native_pagination(service),
            'circular_token_detection': self.has_circular_token_detection(service)
        }

    # ========================================================================
    # Helper Methods for Integration
    # ========================================================================

    def build_paginator_config(
        self,
        service: str,
        action: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Build configuration dict for boto3 paginators.

        Args:
            service: Service name
            action: Optional action name

        Returns:
            Dict suitable for boto3 paginator configuration
        """
        params = self.get_pagination_params(service, action)

        return {
            'PageSize': params['default_page_size'],
            'MaxItems': params['max_items']
        }

    def should_use_native_paginator(
        self,
        service: str,
        client,
        action: str
    ) -> bool:
        """
        Determine if native boto3 paginator should be used.

        Args:
            service: Service name
            client: Boto3 client instance
            action: Action name

        Returns:
            True if native paginator should be used
        """
        # Check if service supports native pagination
        if not self.supports_native_pagination(service):
            return False

        # Check if boto3 client has paginator for this action
        try:
            return hasattr(client, 'can_paginate') and client.can_paginate(action)
        except Exception:
            return False

    def get_pagination_summary(self, service: str) -> Dict[str, Any]:
        """
        Get summary of pagination configuration for service.

        Args:
            service: Service name

        Returns:
            Dict with pagination summary

        Example:
            >>> summary = pagination_engine.get_pagination_summary('sagemaker')
            >>> print(summary)
            {
                'service': 'sagemaker',
                'default_page_size': 100,
                'max_pages': 100,
                'token_field': 'NextToken',
                'has_overrides': False
            }
        """
        try:
            pagination_config = self.config_loader.get_pagination_config(service)
            service_overrides = pagination_config.get('service_overrides', {})

            return {
                'service': service,
                'default_page_size': pagination_config.get('default_page_size', 1000),
                'max_pages': pagination_config.get('max_pages', 100),
                'max_items': pagination_config.get('max_items', 100000),
                'token_field': pagination_config.get('token_field', 'NextToken'),
                'timeout_seconds': pagination_config.get('timeout_seconds', 600),
                'has_overrides': len(service_overrides) > 0,
                'override_actions': list(service_overrides.keys()) if service_overrides else []
            }

        except Exception as e:
            logger.error(f"Error getting pagination summary for {service}: {e}")
            return {
                'service': service,
                'error': str(e)
            }
