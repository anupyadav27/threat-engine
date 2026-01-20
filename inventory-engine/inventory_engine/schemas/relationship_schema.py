"""
Relationship Schema (cspm_relationship.v1)

Canonical relationship model for asset graph edges.
"""

from typing import Dict, Any, Optional, Literal
from pydantic import BaseModel, Field
from enum import Enum


class RelationType(str, Enum):
    """Relationship types for asset graph"""
    CONTAINED_BY = "contained_by"
    CONNECTED_TO = "connected_to"
    ATTACHED_TO = "attached_to"
    CONTROLLED_BY = "controlled_by"
    INTERNET_CONNECTED = "internet_connected"
    LAYER_1 = "1st_layer"
    LAYER_2 = "2nd_layer"
    LAYER_3 = "3rd_layer"
    LAYER_4 = "4th_layer"
    ON_PREM_DATACENTER = "on_prem_datacenter"
    ENCRYPTED_BY = "encrypted_by"
    LOGGING_ENABLED_TO = "logging_enabled_to"
    MEMBER_OF = "member_of"


class Relationship(BaseModel):
    """Canonical relationship record (graph edge)"""
    schema_version: Literal["cspm_relationship.v1"] = "cspm_relationship.v1"
    tenant_id: str = Field(..., description="Tenant identifier")
    scan_run_id: str = Field(..., description="Scan run identifier")
    provider: str = Field(..., description="Cloud provider")
    account_id: str = Field(..., description="Account/subscription/project ID")
    region: Optional[str] = Field(None, description="Region code (optional for cross-region)")
    relation_type: RelationType = Field(..., description="Relationship type")
    from_uid: str = Field(..., description="Source asset resource_uid")
    to_uid: str = Field(..., description="Target asset resource_uid")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Edge properties")
    
    class Config:
        json_schema_extra = {
            "example": {
                "schema_version": "cspm_relationship.v1",
                "tenant_id": "tnt_123",
                "scan_run_id": "scan_01HYYY",
                "provider": "aws",
                "account_id": "588989875114",
                "region": "us-east-1",
                "relation_type": "attached_to",
                "from_uid": "arn:aws:ec2:us-east-1:5889:instance/i-123",
                "to_uid": "arn:aws:ec2:us-east-1:5889:security-group/sg-789",
                "properties": {
                    "direction": "inbound",
                    "protocol": "tcp",
                    "port": "443"
                }
            }
        }

