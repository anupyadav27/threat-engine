"""
Filter Engine - Database-Driven Filtering
==========================================
Apply database-configured filter rules to discovery operations.

Replaces:
- Hardcoded filter logic in service_scanner.py (lines 98-276)
- _apply_aws_managed_filters_at_api_level()
- _filter_aws_managed_resources()

Usage:
    from engine_discoveries.utils.config_loader import DiscoveryConfigLoader
    from engine_discoveries.utils.filter_engine import FilterEngine

    config_loader = DiscoveryConfigLoader(provider='aws')
    filter_engine = FilterEngine(config_loader)

    # Pre-call filtering (modify API params)
    params = filter_engine.apply_api_filters('aws.ec2.describe_snapshots', params, 'ec2')

    # Post-call filtering (filter response items)
    items = filter_engine.apply_response_filters('aws.kms.list_aliases', items, 'kms')
"""

import re
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class FilterEngine:
    """Apply database-driven filter rules to discovery operations"""

    def __init__(self, config_loader):
        """
        Initialize filter engine.

        Args:
            config_loader: DiscoveryConfigLoader instance
        """
        self.config_loader = config_loader

    # ========================================================================
    # API-Level Filters (Pre-Call)
    # ========================================================================

    def apply_api_filters(
        self,
        discovery_id: str,
        params: Dict[str, Any],
        service: str,
        account_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Apply API-level filters to request parameters (pre-call filtering).

        Replaces: _apply_aws_managed_filters_at_api_level()

        Args:
            discovery_id: Discovery ID (e.g., 'aws.ec2.describe_snapshots')
            params: API request parameters dict (will be modified in-place)
            service: Service name (e.g., 'ec2')
            account_id: Optional account ID for context

        Returns:
            Modified params dict

        Example:
            >>> filter_engine.apply_api_filters('aws.ec2.describe_snapshots', {}, 'ec2')
            {'OwnerIds': ['self']}
        """
        try:
            filter_rules = self.config_loader.get_filter_rules(service)
            api_filters = filter_rules.get('api_filters', [])

            if not api_filters:
                logger.debug(f"No API filters for service: {service}")
                return params

            applied_count = 0

            # Sort by priority (lower number = higher priority)
            for rule in sorted(api_filters, key=lambda x: x.get('priority', 100)):
                # Match by discovery_id
                if rule.get('discovery_id') == discovery_id:
                    parameter = rule.get('parameter')
                    value = rule.get('value')

                    if parameter and value is not None:
                        params[parameter] = value
                        applied_count += 1
                        logger.debug(f"Applied API filter: {parameter}={value} for {discovery_id}")

            if applied_count > 0:
                logger.info(f"Applied {applied_count} API filters for {discovery_id}")

        except Exception as e:
            logger.error(f"Error applying API filters for {discovery_id}: {e}")
            # Don't fail discovery on filter error

        return params

    # ========================================================================
    # Response-Level Filters (Post-Call)
    # ========================================================================

    def apply_response_filters(
        self,
        discovery_id: str,
        items: List[Dict[str, Any]],
        service: str,
        account_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Apply response-level filters to discovered items (post-call filtering).

        Replaces: _filter_aws_managed_resources()

        Args:
            discovery_id: Discovery ID (e.g., 'aws.kms.list_aliases')
            items: List of discovered resource items
            service: Service name (e.g., 'kms')
            account_id: Optional account ID for context

        Returns:
            Filtered list of items

        Example:
            >>> items = [
            ...     {'AliasName': 'alias/aws/s3'},
            ...     {'AliasName': 'alias/my-key'}
            ... ]
            >>> filter_engine.apply_response_filters('aws.kms.list_aliases', items, 'kms')
            [{'AliasName': 'alias/my-key'}]  # AWS-managed alias excluded
        """
        if not items:
            return items

        try:
            filter_rules = self.config_loader.get_filter_rules(service)
            response_filters = filter_rules.get('response_filters', [])

            if not response_filters:
                logger.debug(f"No response filters for service: {service}")
                return items

            filtered_items = items
            initial_count = len(items)

            # Sort by priority (lower number = higher priority)
            for rule in sorted(response_filters, key=lambda x: x.get('priority', 100)):
                # Match by discovery_id
                if rule.get('discovery_id') == discovery_id:
                    filtered_items = self._apply_pattern_filter(filtered_items, rule)

            filtered_count = len(filtered_items)
            excluded_count = initial_count - filtered_count

            if excluded_count > 0:
                logger.info(f"Excluded {excluded_count} items for {discovery_id} (kept {filtered_count})")

            return filtered_items

        except Exception as e:
            logger.error(f"Error applying response filters for {discovery_id}: {e}")
            # Return original items on error (fail safe)
            return items

    def _apply_pattern_filter(
        self,
        items: List[Dict[str, Any]],
        rule: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Apply a single pattern-based filter rule.

        Args:
            items: List of items to filter
            rule: Filter rule dict with pattern, field_path, pattern_type, action

        Returns:
            Filtered list of items
        """
        field_path = rule.get('field_path')
        pattern = rule.get('pattern')
        pattern_type = rule.get('pattern_type', 'regex')
        action = rule.get('action', 'exclude')

        if not field_path or not pattern:
            logger.warning(f"Invalid filter rule (missing field_path or pattern): {rule}")
            return items

        filtered_items = []

        for item in items:
            # Extract field value
            field_value = self._extract_field(item, field_path)

            if field_value is None:
                # Keep items where field doesn't exist (unless rule says otherwise)
                filtered_items.append(item)
                continue

            # Check if pattern matches
            matches = self._pattern_matches(str(field_value), pattern, pattern_type)

            # Apply action
            if action == 'exclude':
                # Exclude if matches
                if not matches:
                    filtered_items.append(item)
                else:
                    logger.debug(f"Excluded item: {field_path}={field_value} matches {pattern}")
            elif action == 'include':
                # Include only if matches
                if matches:
                    filtered_items.append(item)
            else:
                # Unknown action - keep item
                filtered_items.append(item)

        return filtered_items

    def _extract_field(
        self,
        item: Dict[str, Any],
        field_path: str
    ) -> Optional[Any]:
        """
        Extract field value from item using dot notation.

        Args:
            item: Resource item dict
            field_path: Field path (e.g., 'Name', 'Tags.Environment')

        Returns:
            Field value or None if not found
        """
        try:
            # Support dot notation for nested fields
            parts = field_path.split('.')
            value = item

            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return None

                if value is None:
                    return None

            return value

        except Exception as e:
            logger.debug(f"Error extracting field '{field_path}': {e}")
            return None

    def _pattern_matches(
        self,
        value: str,
        pattern: str,
        pattern_type: str
    ) -> bool:
        """
        Check if value matches pattern.

        Args:
            value: String value to check
            pattern: Pattern to match
            pattern_type: Type of pattern ('regex', 'prefix', 'suffix', 'contains', 'exact')

        Returns:
            True if matches, False otherwise
        """
        try:
            if pattern_type == 'prefix':
                # Remove leading ^ if present
                clean_pattern = pattern.lstrip('^')
                return value.startswith(clean_pattern)

            elif pattern_type == 'suffix':
                # Remove trailing $ if present
                clean_pattern = pattern.rstrip('$')
                return value.endswith(clean_pattern)

            elif pattern_type == 'contains':
                return pattern in value

            elif pattern_type == 'exact':
                return value == pattern

            elif pattern_type == 'regex':
                # Full regex matching
                return bool(re.match(pattern, value))

            else:
                logger.warning(f"Unknown pattern type: {pattern_type}, using regex")
                return bool(re.match(pattern, value))

        except re.error as e:
            logger.error(f"Invalid regex pattern '{pattern}': {e}")
            return False
        except Exception as e:
            logger.error(f"Error matching pattern '{pattern}' against '{value}': {e}")
            return False

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def has_filters(self, service: str) -> bool:
        """
        Check if service has any configured filters.

        Args:
            service: Service name

        Returns:
            True if service has API or response filters
        """
        try:
            filter_rules = self.config_loader.get_filter_rules(service)
            api_filters = filter_rules.get('api_filters', [])
            response_filters = filter_rules.get('response_filters', [])

            return len(api_filters) > 0 or len(response_filters) > 0

        except Exception:
            return False

    def get_filter_count(self, service: str) -> Dict[str, int]:
        """
        Get count of filters for a service.

        Args:
            service: Service name

        Returns:
            Dict with 'api_filters' and 'response_filters' counts
        """
        try:
            filter_rules = self.config_loader.get_filter_rules(service)
            return {
                'api_filters': len(filter_rules.get('api_filters', [])),
                'response_filters': len(filter_rules.get('response_filters', []))
            }
        except Exception:
            return {'api_filters': 0, 'response_filters': 0}

    def get_filters_for_discovery(
        self,
        discovery_id: str,
        service: str
    ) -> Dict[str, List[Dict]]:
        """
        Get all filters that apply to a specific discovery.

        Args:
            discovery_id: Discovery ID
            service: Service name

        Returns:
            Dict with 'api_filters' and 'response_filters' for this discovery
        """
        try:
            filter_rules = self.config_loader.get_filter_rules(service)

            # Filter to only rules matching this discovery_id
            api_filters = [
                rule for rule in filter_rules.get('api_filters', [])
                if rule.get('discovery_id') == discovery_id
            ]

            response_filters = [
                rule for rule in filter_rules.get('response_filters', [])
                if rule.get('discovery_id') == discovery_id
            ]

            return {
                'api_filters': api_filters,
                'response_filters': response_filters
            }

        except Exception as e:
            logger.error(f"Error getting filters for {discovery_id}: {e}")
            return {'api_filters': [], 'response_filters': []}
