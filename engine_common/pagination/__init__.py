"""
Pagination Engine - Database-driven pagination config for multi-CSP support.

Replaces hardcoded service-specific page sizes and token fields with
database-backed pagination config from the pagination_config table.

Usage:
    from engine_common.pagination import PaginationEngine

    pagination_engine = PaginationEngine(csp='aws')

    # Get pagination config with fallback (action → service → default)
    config = pagination_engine.get_config(service_name='sagemaker', action='list_models')

    # Unified pagination with config-driven parameters
    results = pagination_engine.paginate(client, 'list_models', params)
"""

# Will be imported once pagination_engine.py and pagination_config.py are created
# from .pagination_engine import PaginationEngine
# from .pagination_config import PaginationConfig

# __all__ = ['PaginationEngine', 'PaginationConfig']
