"""
Filter Engine - Database-driven filter rules for multi-CSP support.

Replaces hardcoded if/elif chains in service_scanner.py with
database-backed filter rules from the filter_rules table.

Usage:
    from engine_common.filters import FilterEngine

    filter_engine = FilterEngine(csp='aws')

    # Apply pre-call API filters
    params = filter_engine.apply_api_filters('aws.ec2.describe_snapshots', params)

    # Apply post-call response filters
    filtered_items = filter_engine.apply_response_filters('aws.kms.list_aliases', items)
"""

# Will be imported once filter_engine.py and filter_rules.py are created
# from .filter_engine import FilterEngine
# from .filter_rules import FilterRule

# __all__ = ['FilterEngine', 'FilterRule']
