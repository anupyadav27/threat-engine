"""
Check Validator - Runtime validation for check rules

This module provides validation for check rules before and during execution.
Uses the same validation logic as the offline validation scripts to ensure
consistency between development/testing and production.

Usage:
    from engine.check_validator import CheckValidator

    validator = CheckValidator(discovery_cache)

    # Pre-execution validation
    if validator.validate_check(check_config):
        # Run check
        results = execute_check(check_config, discovery_output)

    # Runtime validation
    validator.validate_field_access(item, field_ref)
"""

import logging
import re
from typing import Dict, List, Set, Optional, Any, Tuple

logger = logging.getLogger(__name__)

# Valid operators (must match validation scripts)
VALID_OPERATORS = {
    'equals', 'not_equals', 'eq', 'ne',
    'greater_than', 'less_than', 'gte', 'lte', 'gt', 'lt',
    'exists', 'not_exists',
    'contains', 'not_contains', 'starts_with', 'ends_with',
    'regex', 'not_regex',
    'in', 'not_in', 'contains_all', 'contains_any',
    'all', 'any', 'not', 'none',
    'is_null', 'is_not_null', 'is_empty', 'is_not_empty',
    'length_equals', 'length_greater_than', 'length_less_than'
}


class ValidationError(Exception):
    """Check validation error"""
    pass


class CheckValidator:
    """Validates check rules against discovery configurations"""

    def __init__(self, discovery_cache: Optional[Dict] = None, strict_mode: bool = False):
        """
        Initialize validator

        Args:
            discovery_cache: Cache of discovery configurations {service: discovery_data}
            strict_mode: If True, raise exceptions on validation errors
                        If False, log warnings and continue
        """
        self.discovery_cache = discovery_cache or {}
        self.strict_mode = strict_mode
        self.dependency_graph = {}
        self._build_dependency_graph()

    def _build_dependency_graph(self):
        """Build dependency graph from discovery cache"""
        for service, discovery_data in self.discovery_cache.items():
            discoveries = discovery_data.get('discovery', [])

            for disc in discoveries:
                disc_id = disc.get('discovery_id')
                if not disc_id:
                    continue

                self.dependency_graph[disc_id] = {
                    'service': service,
                    'depends_on': disc.get('for_each'),
                    'emit_fields': self._extract_emit_fields(disc),
                    'emit_item_fields': self._extract_emit_item_fields(disc)
                }

    def _extract_emit_fields(self, discovery: Dict) -> Set[str]:
        """Extract fields from discovery emit configuration"""
        fields = set()
        emit = discovery.get('emit', {})

        # Get items_for field
        items_for = emit.get('items_for', '')
        if items_for and '{{' in items_for:
            # Extract field name from {{ response.FieldName }}
            match = re.search(r'response\.(\w+)', items_for)
            if match:
                fields.add(match.group(1))

        return fields

    def _extract_emit_item_fields(self, discovery: Dict) -> Set[str]:
        """Extract item fields from discovery emit.item configuration"""
        fields = set()
        emit = discovery.get('emit', {})
        item = emit.get('item', {})

        if isinstance(item, dict):
            fields = set(item.keys())

        return fields

    def get_dependency_chain(self, discovery_id: str, visited: Set[str] = None) -> List[str]:
        """Get complete dependency chain for a discovery operation"""
        if visited is None:
            visited = set()

        if discovery_id in visited:
            logger.warning(f"Circular dependency detected: {discovery_id}")
            return []

        visited.add(discovery_id)
        chain = [discovery_id]

        if discovery_id in self.dependency_graph:
            depends_on = self.dependency_graph[discovery_id]['depends_on']
            if depends_on:
                chain.extend(self.get_dependency_chain(depends_on, visited))

        return chain

    def extract_discovery_refs(self, check_config: Dict) -> Set[str]:
        """Extract all discovery operation references from check"""
        refs = set()

        def extract_refs(obj):
            if isinstance(obj, dict):
                if 'for_each' in obj:
                    refs.add(obj['for_each'])
                if 'discovery_id' in obj:
                    refs.add(obj['discovery_id'])
                for value in obj.values():
                    extract_refs(value)
            elif isinstance(obj, list):
                for item in obj:
                    extract_refs(item)

        extract_refs(check_config)
        return refs

    def extract_field_refs(self, conditions: Dict) -> Set[str]:
        """Extract all field references from check conditions"""
        fields = set()

        def extract_fields(obj):
            if isinstance(obj, dict):
                if 'var' in obj:
                    var = obj['var']
                    if isinstance(var, str):
                        fields.add(var)
                for value in obj.values():
                    extract_fields(value)
            elif isinstance(obj, list):
                for item in obj:
                    extract_fields(item)

        extract_fields(conditions)
        return fields

    def parse_field_name(self, field_ref: str) -> str:
        """Parse field reference to get field name (item.Status -> Status)"""
        if '.' in field_ref:
            parts = field_ref.split('.')
            if len(parts) == 2 and parts[0] == 'item':
                return parts[1]
            return parts[-1]
        return field_ref

    def validate_operators(self, conditions: Dict, path: str = "conditions") -> List[str]:
        """Validate operators are valid. Returns list of errors."""
        errors = []

        def check_operators(obj, current_path):
            if isinstance(obj, dict):
                if 'op' in obj:
                    op = obj['op']
                    if op not in VALID_OPERATORS:
                        errors.append(f"Invalid operator '{op}' at {current_path}")

                for key, value in obj.items():
                    check_operators(value, f"{current_path}.{key}")
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    check_operators(item, f"{current_path}[{idx}]")

        check_operators(conditions, path)
        return errors

    def validate_dependency_chain(self, discovery_refs: Set[str]) -> Tuple[bool, List[str]]:
        """Validate complete dependency chain exists. Returns (valid, errors)."""
        errors = []

        for disc_ref in discovery_refs:
            # Check if discovery exists
            if disc_ref not in self.dependency_graph:
                errors.append(f"Discovery operation '{disc_ref}' not found")
                continue

            # Check complete dependency chain
            chain = self.get_dependency_chain(disc_ref)
            for dep_id in chain:
                if dep_id not in self.dependency_graph:
                    errors.append(f"Dependency chain broken: '{dep_id}' not found (required by '{disc_ref}')")

        return (len(errors) == 0, errors)

    def validate_field_availability(self, discovery_ref: str, field_refs: Set[str]) -> Tuple[bool, List[str]]:
        """Validate fields are available in discovery emit. Returns (valid, warnings)."""
        warnings = []

        if discovery_ref not in self.dependency_graph:
            return (False, [f"Discovery {discovery_ref} not found"])

        # Get complete dependency chain
        chain = self.get_dependency_chain(discovery_ref)

        # Collect all available fields from entire chain
        available_fields = set()
        for dep_id in chain:
            if dep_id in self.dependency_graph:
                dep_data = self.dependency_graph[dep_id]
                available_fields.update(dep_data['emit_fields'])
                available_fields.update(dep_data['emit_item_fields'])

        # Validate each field reference
        for field_ref in field_refs:
            field_name = self.parse_field_name(field_ref)

            # Skip 'item' and 'response' themselves
            if field_name in ['item', 'response']:
                continue

            if field_name not in available_fields and available_fields:
                warnings.append(
                    f"Field '{field_name}' may not exist in '{discovery_ref}'. "
                    f"Available: {', '.join(sorted(available_fields))}"
                )

        return (len(warnings) == 0, warnings)

    def validate_check(self, check_config: Dict, service: str = None, rule_id: str = None) -> bool:
        """
        Validate check configuration before execution

        Args:
            check_config: Check configuration dict
            service: Service name (for logging)
            rule_id: Rule ID (for logging)

        Returns:
            True if valid, False otherwise

        Raises:
            ValidationError: If strict_mode=True and validation fails
        """
        context = f"{service}.{rule_id}" if service and rule_id else "check"
        errors = []
        warnings = []

        # Extract discovery references
        discovery_refs = self.extract_discovery_refs(check_config)

        if not discovery_refs:
            msg = f"{context}: No discovery references found"
            logger.warning(msg)
            warnings.append(msg)

        # Validate dependency chains
        chain_valid, chain_errors = self.validate_dependency_chain(discovery_refs)
        errors.extend(chain_errors)

        # Validate operators
        conditions = check_config.get('conditions', {})
        if conditions:
            op_errors = self.validate_operators(conditions)
            errors.extend(op_errors)

            # Extract and validate fields
            field_refs = self.extract_field_refs(conditions)

            for_each = check_config.get('for_each')
            if for_each and for_each in self.dependency_graph:
                field_valid, field_warnings = self.validate_field_availability(for_each, field_refs)
                warnings.extend(field_warnings)

        # Log results
        if errors:
            for error in errors:
                logger.error(f"{context}: {error}")

            if self.strict_mode:
                raise ValidationError(f"{context}: Validation failed - {'; '.join(errors)}")
            return False

        if warnings:
            for warning in warnings:
                logger.warning(f"{context}: {warning}")

        if not errors and not warnings:
            logger.debug(f"{context}: Validation passed")

        return len(errors) == 0

    def has_field(self, item: Dict, field_ref: str) -> bool:
        """Check if field exists in item (supports nested access)"""
        if not isinstance(item, dict):
            return False

        # Parse field reference
        if '.' in field_ref:
            parts = field_ref.split('.')
            if parts[0] == 'item':
                parts = parts[1:]  # Remove 'item' prefix

            # Navigate nested structure
            current = item
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return False
            return True
        else:
            return field_ref in item

    def get_field_value(self, item: Dict, field_ref: str, default: Any = None) -> Any:
        """Get field value from item (supports nested access)"""
        if not self.has_field(item, field_ref):
            return default

        # Parse field reference
        if '.' in field_ref:
            parts = field_ref.split('.')
            if parts[0] == 'item':
                parts = parts[1:]

            # Navigate nested structure
            current = item
            for part in parts:
                current = current.get(part, default)
                if current is default:
                    return default
            return current
        else:
            return item.get(field_ref, default)

    def validate_field_access(self, item: Dict, field_ref: str) -> Tuple[bool, Optional[str]]:
        """
        Validate field access at runtime

        Args:
            item: Item dict from discovery output
            field_ref: Field reference (e.g., 'item.Status')

        Returns:
            (success, error_message)
        """
        if not self.has_field(item, field_ref):
            field_name = self.parse_field_name(field_ref)
            error = f"Field '{field_name}' not found in item"

            if self.strict_mode:
                raise ValidationError(error)

            logger.warning(error)
            return (False, error)

        return (True, None)


def create_validator_from_discovery_cache(discovery_cache: Dict, strict_mode: bool = False) -> CheckValidator:
    """
    Create a CheckValidator from discovery cache

    Args:
        discovery_cache: Discovery configurations {service: discovery_data}
        strict_mode: If True, raise exceptions on validation errors

    Returns:
        CheckValidator instance
    """
    return CheckValidator(discovery_cache, strict_mode)


# Convenience functions for check engine integration
def validate_check_before_execution(check_config: Dict, discovery_cache: Dict,
                                    service: str = None, rule_id: str = None,
                                    strict: bool = False) -> bool:
    """
    Validate check before execution (convenience function)

    Args:
        check_config: Check configuration
        discovery_cache: Discovery configurations
        service: Service name
        rule_id: Rule ID
        strict: If True, raise on validation errors

    Returns:
        True if valid, False otherwise
    """
    validator = CheckValidator(discovery_cache, strict_mode=strict)
    return validator.validate_check(check_config, service, rule_id)


def safe_get_field(item: Dict, field_ref: str, discovery_cache: Dict = None, default: Any = None) -> Any:
    """
    Safely get field value from item (convenience function)

    Args:
        item: Item dict
        field_ref: Field reference
        discovery_cache: Discovery cache (for validation logging)
        default: Default value if field not found

    Returns:
        Field value or default
    """
    validator = CheckValidator(discovery_cache or {}, strict_mode=False)
    return validator.get_field_value(item, field_ref, default)
