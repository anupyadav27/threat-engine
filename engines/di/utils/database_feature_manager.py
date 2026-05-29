"""
Database Feature Manager
=========================
Replaces ServiceFeatureManager by querying rule_discoveries table.

Eliminates dependency on service_list.json files - database is the ONLY source of truth.

Usage:
    from engine_discoveries.utils.database_feature_manager import DatabaseFeatureManager

    feature_manager = DatabaseFeatureManager(provider='aws')
    enabled_services = feature_manager.get_enabled_services('discovery')

    # Check if specific service has feature enabled
    if feature_manager.is_feature_enabled('ec2', 'discovery'):
        # Run discovery for EC2
        ...
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)


class DatabaseFeatureManager:
    """
    Replacement for ServiceFeatureManager.

    Queries rule_discoveries table instead of loading service_list.json.
    Provides database-driven service enablement and feature detection.
    """

    def __init__(self, provider: str = 'aws', db_config: Optional[Dict[str, Any]] = None):
        """
        Initialize DatabaseFeatureManager.

        Args:
            provider: Cloud provider (default: 'aws')
            db_config: Database connection config. If None, reads from env.
        """
        self.provider = provider
        self._conn = None
        self._cache = {}  # Cache for performance

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
        """Get database connection (lazy initialization)"""
        if self._conn is None or self._conn.closed:
            try:
                self._conn = psycopg2.connect(**self.db_config)
                logger.debug(f"Connected to database: {self.db_config['database']}")
            except Exception as e:
                logger.error(f"Database connection failed: {e}")
                raise

        return self._conn

    def get_enabled_services(self, feature: str = 'discovery') -> List[str]:
        """
        Get list of services where feature is enabled.

        Args:
            feature: Feature name ('discovery', 'checks', 'deviation', 'drift')

        Returns:
            List of service names, ordered by priority (high to low) then alphabetically

        Example:
            >>> manager = DatabaseFeatureManager(provider='aws')
            >>> services = manager.get_enabled_services('discovery')
            >>> print(services)
            ['ec2', 's3', 'iam', 'lambda', ...]
        """
        cache_key = f"{self.provider}:{feature}:enabled_services"

        # Check cache first
        if cache_key in self._cache:
            logger.debug(f"Cache hit for enabled services: {feature}")
            return self._cache[cache_key]

        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            query = """
                SELECT service
                FROM rule_discoveries
                WHERE provider = %s
                  AND is_active = TRUE
                  AND features->%s->>'enabled' = 'true'
                ORDER BY
                  CAST(features->%s->>'priority' AS INTEGER) ASC,
                  service ASC
            """

            cursor.execute(query, (self.provider, feature, feature))
            rows = cursor.fetchall()
            cursor.close()

            services = [row[0] for row in rows]

            # Cache the result
            self._cache[cache_key] = services

            logger.info(f"Found {len(services)} services with {feature} enabled for provider '{self.provider}'")

            return services

        except Exception as e:
            logger.error(f"Error fetching enabled services for feature '{feature}': {e}")
            # Return empty list on error (graceful degradation)
            return []

    def is_feature_enabled(self, service: str, feature: str) -> bool:
        """
        Check if feature is enabled for a specific service.

        Args:
            service: Service name (e.g., 'ec2', 'iam')
            feature: Feature name ('discovery', 'checks', 'deviation', 'drift')

        Returns:
            True if feature is enabled and service is active, False otherwise

        Example:
            >>> manager = DatabaseFeatureManager(provider='aws')
            >>> if manager.is_feature_enabled('ec2', 'discovery'):
            ...     run_discovery('ec2')
        """
        cache_key = f"{self.provider}:{service}:{feature}:enabled"

        # Check cache first
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            query = """
                SELECT features->%s->>'enabled' as enabled
                FROM rule_discoveries
                WHERE service = %s
                  AND provider = %s
                  AND is_active = TRUE
                LIMIT 1
            """

            cursor.execute(query, (feature, service, self.provider))
            row = cursor.fetchone()
            cursor.close()

            if row:
                enabled = row[0] == 'true'
                self._cache[cache_key] = enabled
                return enabled
            else:
                # Service not found or not active
                self._cache[cache_key] = False
                return False

        except Exception as e:
            logger.error(f"Error checking feature '{feature}' for service '{service}': {e}")
            # Default to False on error (safe default)
            return False

    def get_service_priority(self, service: str, feature: str) -> int:
        """
        Get priority for a service's feature.

        Args:
            service: Service name
            feature: Feature name

        Returns:
            Priority value (1=high, 2=medium, 3=low), or 999 if not found

        Example:
            >>> manager = DatabaseFeatureManager(provider='aws')
            >>> priority = manager.get_service_priority('ec2', 'discovery')
            >>> print(priority)  # 1 (high priority)
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            query = """
                SELECT features->%s->>'priority' as priority
                FROM rule_discoveries
                WHERE service = %s
                  AND provider = %s
                  AND is_active = TRUE
                LIMIT 1
            """

            cursor.execute(query, (feature, service, self.provider))
            row = cursor.fetchone()
            cursor.close()

            if row and row[0]:
                return int(row[0])
            else:
                return 999  # Default low priority

        except Exception as e:
            logger.error(f"Error getting priority for service '{service}': {e}")
            return 999  # Default low priority on error

    def filter_services_by_features(self, services: List[str], features: List[str]) -> List[str]:
        """
        Filter service list by enabled features.

        Args:
            services: List of service names to filter
            features: List of feature names (all must be enabled)

        Returns:
            Filtered list of services that have ALL features enabled

        Example:
            >>> manager = DatabaseFeatureManager(provider='aws')
            >>> services = ['ec2', 's3', 'iam', 'lambda']
            >>> # Get services that have both discovery AND checks enabled
            >>> filtered = manager.filter_services_by_features(services, ['discovery', 'checks'])
        """
        if not services or not features:
            return []

        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Build dynamic query with multiple feature checks
            feature_conditions = []
            params = []

            for feature in features:
                feature_conditions.append(f"features->%s->>'enabled' = 'true'")
                params.append(feature)

            query = f"""
                SELECT service
                FROM rule_discoveries
                WHERE provider = %s
                  AND is_active = TRUE
                  AND service = ANY(%s)
                  AND {' AND '.join(feature_conditions)}
                ORDER BY service ASC
            """

            params = [self.provider, services] + params

            cursor.execute(query, params)
            rows = cursor.fetchall()
            cursor.close()

            filtered_services = [row[0] for row in rows]

            logger.info(f"Filtered {len(services)} services to {len(filtered_services)} with features {features}")

            return filtered_services

        except Exception as e:
            logger.error(f"Error filtering services by features {features}: {e}")
            # Return empty list on error (safe default)
            return []

    def get_all_services(self, active_only: bool = True) -> List[str]:
        """
        Get all services for the provider.

        Args:
            active_only: If True, only return active services

        Returns:
            List of all service names

        Example:
            >>> manager = DatabaseFeatureManager(provider='aws')
            >>> all_services = manager.get_all_services()
            >>> print(f"Total AWS services: {len(all_services)}")
        """
        cache_key = f"{self.provider}:all_services:active={active_only}"

        # Check cache first
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            if active_only:
                query = """
                    SELECT service
                    FROM rule_discoveries
                    WHERE provider = %s AND is_active = TRUE
                    ORDER BY service ASC
                """
                cursor.execute(query, (self.provider,))
            else:
                query = """
                    SELECT service
                    FROM rule_discoveries
                    WHERE provider = %s
                    ORDER BY service ASC
                """
                cursor.execute(query, (self.provider,))

            rows = cursor.fetchall()
            cursor.close()

            services = [row[0] for row in rows]

            # Cache the result
            self._cache[cache_key] = services

            logger.info(f"Found {len(services)} total services for provider '{self.provider}' (active_only={active_only})")

            return services

        except Exception as e:
            logger.error(f"Error fetching all services: {e}")
            return []

    def get_service_features(self, service: str) -> Dict[str, Dict[str, Any]]:
        """
        Get all feature configurations for a service.

        Args:
            service: Service name

        Returns:
            Dict mapping feature names to their config (enabled, priority)

        Example:
            >>> manager = DatabaseFeatureManager(provider='aws')
            >>> features = manager.get_service_features('ec2')
            >>> print(features)
            {
                'discovery': {'enabled': True, 'priority': 1},
                'checks': {'enabled': True, 'priority': 1},
                'deviation': {'enabled': False, 'priority': 3},
                'drift': {'enabled': False, 'priority': 3}
            }
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor(cursor_factory=RealDictCursor)

            query = """
                SELECT features
                FROM rule_discoveries
                WHERE service = %s
                  AND provider = %s
                  AND is_active = TRUE
                LIMIT 1
            """

            cursor.execute(query, (service, self.provider))
            row = cursor.fetchone()
            cursor.close()

            if row and row['features']:
                return dict(row['features'])
            else:
                # Return default features if not found
                return {
                    'discovery': {'enabled': False, 'priority': 1},
                    'checks': {'enabled': False, 'priority': 1},
                    'deviation': {'enabled': False, 'priority': 3},
                    'drift': {'enabled': False, 'priority': 3}
                }

        except Exception as e:
            logger.error(f"Error getting features for service '{service}': {e}")
            return {}

    def clear_cache(self):
        """Clear internal cache"""
        self._cache.clear()
        logger.debug("Cleared DatabaseFeatureManager cache")

    def close(self):
        """Close database connection"""
        if self._conn and not self._conn.closed:
            self._conn.close()
            logger.debug("Closed database connection")

    def __del__(self):
        """Cleanup on deletion"""
        self.close()


# Singleton instance for convenience
_default_manager = None


def get_default_manager(provider: str = 'aws') -> DatabaseFeatureManager:
    """
    Get the default singleton DatabaseFeatureManager instance.

    Args:
        provider: Cloud provider

    Returns:
        DatabaseFeatureManager instance
    """
    global _default_manager
    if _default_manager is None:
        _default_manager = DatabaseFeatureManager(provider=provider)
    return _default_manager
