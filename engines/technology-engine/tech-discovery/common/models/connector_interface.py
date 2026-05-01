"""
Base connector interface for all technology providers.
Every scanner must implement TechScanner.
Mirrors: engines/discoveries/common/models/provider_interface.py
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class AuthenticationError(Exception):
    """Raised when credential validation or connection fails."""


class DiscoveryError(Exception):
    """Raised when a discovery query/command fails critically."""


@dataclass
class TechFinding:
    """One raw discovery result row — maps to tech_discovery_findings."""
    finding_id:      str
    scan_run_id:     str
    tenant_id:       str
    account_id:      str
    credential_ref:  str
    credential_type: str
    provider:        str          # = tech_type (postgres, ubuntu, cisco_ios, ...)
    tech_category:   str          # = category (db, linux, network, ...)
    region:          str          # host:port for on-prem
    resource_uid:    str
    resource_type:   str
    discovery_id:    str
    raw_data:        Dict[str, Any] = field(default_factory=dict)
    error_message:   Optional[str] = None
    severity:        str = "info"
    status:          str = "active"


class TechScanner(ABC):
    """Abstract base class for all technology category scanners."""

    def __init__(
        self,
        scan_run_id: str,
        account_id: str,
        credential: Dict[str, Any],
        db_manager: Any,
    ) -> None:
        self.scan_run_id  = scan_run_id
        self.account_id   = account_id
        self.credential   = credential
        self.db_manager   = db_manager
        self.tech_type    = credential["tech_type"]
        self.tech_category = credential["tech_category"]
        self.tenant_id    = credential["tenant_id"]
        self.host         = credential.get("host", "")
        self.port         = credential.get("port")

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the technology. Raise AuthenticationError on failure."""

    @abstractmethod
    async def discover(self) -> List[TechFinding]:
        """Execute YAML-driven discovery queries. Return list of TechFinding."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Cleanly close connection."""

    def _build_finding(
        self,
        discovery_id: str,
        resource_uid: str,
        resource_type: str,
        raw_data: Dict[str, Any],
        error_message: Optional[str] = None,
    ) -> TechFinding:
        """Convenience factory — creates a TechFinding with all standard fields pre-filled."""
        import hashlib
        finding_id = hashlib.sha256(
            f"{discovery_id}|{resource_uid}|{self.scan_run_id}".encode()
        ).hexdigest()[:16]

        return TechFinding(
            finding_id      = finding_id,
            scan_run_id     = self.scan_run_id,
            tenant_id       = self.tenant_id,
            account_id      = self.account_id,
            credential_ref  = self.credential.get("credential_ref", ""),
            credential_type = self.credential.get("credential_type", ""),
            provider        = self.tech_type,
            tech_category   = self.tech_category,
            region          = f"{self.host}:{self.port}" if self.port else self.host,
            resource_uid    = resource_uid,
            resource_type   = resource_type,
            discovery_id    = discovery_id,
            raw_data        = raw_data,
            error_message   = error_message,
        )
