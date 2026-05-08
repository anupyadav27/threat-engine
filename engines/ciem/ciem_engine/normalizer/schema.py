"""
Normalized Event Schema — OCSF-aligned.

All log types (CloudTrail, VPC Flow, S3 Access, ALB, WAF, DNS) are
normalized to this single schema. Downstream engines query this schema
without knowing the original log format.

Based on Open Cybersecurity Schema Framework (OCSF) v1.1
with simplifications for CSPM use case.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum


class EventCategory(str, Enum):
    """High-level event categories (OCSF classes)."""
    API_ACTIVITY = "api_activity"           # CloudTrail management events
    DATA_ACCESS = "data_access"             # S3 GetObject, RDS queries
    NETWORK_ACTIVITY = "network_activity"   # VPC flow logs
    HTTP_ACTIVITY = "http_activity"         # ALB/CloudFront access logs
    DNS_ACTIVITY = "dns_activity"           # Route53 query logs
    SECURITY_FINDING = "security_finding"   # WAF blocks, GuardDuty
    AUTH_ACTIVITY = "auth_activity"         # Console logins, AssumeRole
    APPLICATION_ACTIVITY = "application_activity"  # Lambda, container logs
    AUDIT_ACTIVITY = "audit_activity"       # RDS audit, EKS audit


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Actor:
    """Who performed the action."""
    principal: str = ""          # IAM ARN or username
    principal_type: str = ""     # iam_role, iam_user, root, service, anonymous
    account_id: str = ""         # AWS account
    session_name: str = ""       # AssumedRole session name
    ip_address: str = ""         # Source IP
    user_agent: str = ""         # User agent string
    mfa_used: Optional[bool] = None
    geo_country: str = ""        # From GeoIP enrichment
    geo_city: str = ""


@dataclass
class Resource:
    """What was the target of the action."""
    uid: str = ""                # ARN or unique identifier
    resource_type: str = ""      # ec2.instance, s3.bucket, iam.role
    name: str = ""               # Human-readable name
    account_id: str = ""
    region: str = ""


@dataclass
class NetworkInfo:
    """Network-level details (VPC flow, ALB)."""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""           # tcp, udp, icmp
    direction: str = ""          # ingress, egress
    bytes_in: int = 0
    bytes_out: int = 0
    packets: int = 0
    flow_action: str = ""        # ACCEPT, REJECT


@dataclass
class HttpInfo:
    """HTTP-level details (ALB, CloudFront, WAF)."""
    method: str = ""             # GET, POST, PUT
    url: str = ""                # Request URL
    status_code: int = 0         # 200, 403, 500
    response_time_ms: int = 0
    host: str = ""               # Target host
    referer: str = ""
    content_type: str = ""


@dataclass
class NormalizedEvent:
    """Single normalized log event — all log types map to this."""

    # Identity
    event_id: str = ""           # Unique event ID
    scan_run_id: str = ""
    tenant_id: str = ""

    # Classification
    category: str = ""           # EventCategory value
    source_type: str = ""        # cloudtrail, vpc_flow, s3_access, alb, waf, dns
    severity: str = "info"       # Severity value

    # Time
    event_time: Optional[datetime] = None
    ingestion_time: Optional[datetime] = None

    # What happened
    service: str = ""            # aws service: s3, ec2, iam, rds
    operation: str = ""          # API action: GetObject, RunInstances
    outcome: str = "unknown"     # EventOutcome value
    error_code: str = ""         # AccessDenied, NoSuchKey
    error_message: str = ""

    # Who
    actor: Actor = field(default_factory=Actor)

    # Target
    resource: Resource = field(default_factory=Resource)

    # Network (VPC flow, ALB)
    network: Optional[NetworkInfo] = None

    # HTTP (ALB, CloudFront, WAF)
    http: Optional[HttpInfo] = None

    # Source metadata
    source_bucket: str = ""      # S3 bucket where log was read from
    source_key: str = ""         # S3 key of the log file
    source_region: str = ""      # Region where log was generated

    # Enrichment
    asset_matched: bool = False  # True if resource matched inventory
    risk_indicators: List[str] = field(default_factory=list)

    # Raw (for debugging)
    raw_event: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for DB storage."""
        d = asdict(self)
        # Convert datetime to ISO string
        if d.get("event_time"):
            d["event_time"] = d["event_time"].isoformat()
        if d.get("ingestion_time"):
            d["ingestion_time"] = d["ingestion_time"].isoformat()
        return d
