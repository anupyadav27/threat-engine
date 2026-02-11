"""
engine_auth — Shared authentication and authorization package.

Used by:
- Django portals (user portal, admin portal) via engine_auth.django
- FastAPI services (API gateway, engines) via engine_auth.fastapi

Core concepts:
- AuthContext: dataclass representing authenticated user + permissions + scope
- Permissions use {scope}:{feature}:{action} format (e.g., "tenant:threats:read")
- Scope resolution at login time, cached in user_sessions for zero-query auth
"""

__version__ = "1.0.0"
