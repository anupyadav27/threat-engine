"""
AuthContext — the central data structure for authenticated requests.

Created once at login time (from DB), cached in user_sessions,
and reconstructed from cache on every subsequent request (zero DB queries).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import json


@dataclass
class AuthContext:
    """Represents an authenticated user with their permissions and scope."""

    user_id: str
    email: str
    role: str                                   # e.g., "platform_admin", "org_admin"
    level: int                                  # 1=platform, 2=org, 3=group, 4=tenant, 5=account
    scope_level: str                            # "platform", "organization", "tenant", "account"
    permissions: list[str] = field(default_factory=list)   # ["org:users:write", ...]
    org_ids: Optional[list[str]] = None         # None = unrestricted (platform_admin)
    tenant_ids: Optional[list[str]] = None      # None = unrestricted
    account_ids: Optional[list[str]] = None     # None = unrestricted

    # ── Permission checks ────────────────────────────────────────────

    def has_permission(self, key: str) -> bool:
        """Check if this user has a specific permission."""
        return key in self.permissions

    def has_any_permission(self, *keys: str) -> bool:
        """Check if user has ANY of the given permissions."""
        return any(k in self.permissions for k in keys)

    def has_all_permissions(self, *keys: str) -> bool:
        """Check if user has ALL of the given permissions."""
        return all(k in self.permissions for k in keys)

    def has_feature_access(self, feature: str, action: str = "read") -> bool:
        """Check if user can {action} on {feature} at any scope level."""
        for scope in ("platform", "org", "tenant", "account"):
            if f"{scope}:{feature}:{action}" in self.permissions:
                return True
        return False

    # ── Scope checks ─────────────────────────────────────────────────

    def can_access_org(self, org_id: str) -> bool:
        """Check if user can access this organization."""
        if self.org_ids is None:
            return True  # unrestricted (platform level)
        return org_id in self.org_ids

    def can_access_tenant(self, tenant_id: str) -> bool:
        """Check if user can access this tenant."""
        if self.tenant_ids is None:
            return True  # unrestricted
        return tenant_id in self.tenant_ids

    def can_access_account(self, account_id: str) -> bool:
        """Check if user can access this account."""
        if self.account_ids is None:
            return True  # unrestricted
        return account_id in self.account_ids

    def is_platform_level(self) -> bool:
        """Is this a platform-level user (unrestricted access)?"""
        return self.scope_level == "platform"

    # ── Serialization ────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialize for JSON (e.g., X-Auth-Context header, /api/auth/me/)."""
        return {
            "user_id": self.user_id,
            "email": self.email,
            "role": self.role,
            "level": self.level,
            "scope_level": self.scope_level,
            "permissions": self.permissions,
            "org_ids": self.org_ids,
            "tenant_ids": self.tenant_ids,
            "account_ids": self.account_ids,
        }

    def to_header_json(self) -> str:
        """Serialize for X-Auth-Context HTTP header."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "AuthContext":
        """Reconstruct from dict (e.g., from cached session or header)."""
        return cls(
            user_id=data["user_id"],
            email=data["email"],
            role=data["role"],
            level=data["level"],
            scope_level=data["scope_level"],
            permissions=data.get("permissions", []),
            org_ids=data.get("org_ids"),
            tenant_ids=data.get("tenant_ids"),
            account_ids=data.get("account_ids"),
        )

    @classmethod
    def from_session_cache(
        cls,
        user_id: str,
        email: str,
        role_name: str,
        role_level: int,
        role_scope_level: str,
        permissions_cache: list,
        scope_cache: dict,
    ) -> "AuthContext":
        """Build from user_sessions cached fields (the fast path)."""
        return cls(
            user_id=user_id,
            email=email,
            role=role_name,
            level=role_level,
            scope_level=role_scope_level,
            permissions=permissions_cache or [],
            org_ids=scope_cache.get("org_ids") if scope_cache else None,
            tenant_ids=scope_cache.get("tenant_ids") if scope_cache else None,
            account_ids=scope_cache.get("account_ids") if scope_cache else None,
        )
