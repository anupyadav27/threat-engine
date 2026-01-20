"""
Relationship Builder

Builds relationship edges from normalized assets.
"""

from typing import List, Dict, Any
from ..schemas.asset_schema import Asset, Provider
from ..schemas.relationship_schema import Relationship, RelationType


class RelationshipBuilder:
    """Builds relationships between assets"""
    
    def __init__(self, tenant_id: str, scan_run_id: str):
        self.tenant_id = tenant_id
        self.scan_run_id = scan_run_id
    
    def build_relationships(self, assets: List[Asset]) -> List[Relationship]:
        """
        Build relationships from assets.
        
        Relationship patterns:
        - Network containment: vpc contained_by account, subnet contained_by vpc
        - Security: security_group attached_to eni/instance
        - Internet exposure: internet_connected edge
        - Identity: role attached_to policy, user member_of group
        - Data: bucket encrypted_by kms_key
        """
        relationships = []
        
        # Group assets by type for efficient lookup
        assets_by_uid = {asset.resource_uid: asset for asset in assets}
        assets_by_type = {}
        for asset in assets:
            asset_type = asset.resource_type
            if asset_type not in assets_by_type:
                assets_by_type[asset_type] = []
            assets_by_type[asset_type].append(asset)
        
        # Build network containment relationships
        relationships.extend(self._build_network_containment(assets_by_type))
        
        # Build security relationships
        relationships.extend(self._build_security_relationships(assets_by_type))
        
        # Build internet exposure relationships
        relationships.extend(self._build_internet_exposure(assets_by_type))
        
        # Build identity relationships
        relationships.extend(self._build_identity_relationships(assets_by_type))
        
        # Build data relationships
        relationships.extend(self._build_data_relationships(assets_by_type))
        
        return relationships
    
    def _build_network_containment(self, assets_by_type: Dict[str, List[Asset]]) -> List[Relationship]:
        """Build network containment relationships"""
        relationships = []
        
        # VPC contained_by account
        vpcs = assets_by_type.get("ec2.vpc", [])
        for vpc in vpcs:
            # Account relationship (implicit, account_id is in asset)
            pass  # Account is not an asset, so skip
        
        # Subnet contained_by VPC
        subnets = assets_by_type.get("ec2.subnet", [])
        for subnet in subnets:
            vpc_id = subnet.metadata.get("vpc_id")
            if vpc_id:
                # Find VPC asset
                vpc_uid = f"arn:aws:ec2:{subnet.region}:{subnet.account_id}:vpc/{vpc_id}"
                relationships.append(Relationship(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.scan_run_id,
                    provider=subnet.provider.value,
                    account_id=subnet.account_id,
                    region=subnet.region,
                    relation_type=RelationType.CONTAINED_BY,
                    from_uid=subnet.resource_uid,
                    to_uid=vpc_uid
                ))
        
        # ENI attached_to subnet
        enis = assets_by_type.get("ec2.network-interface", [])
        for eni in enis:
            subnet_id = eni.metadata.get("subnet_id")
            if subnet_id:
                subnet_uid = f"arn:aws:ec2:{eni.region}:{eni.account_id}:subnet/{subnet_id}"
                relationships.append(Relationship(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.scan_run_id,
                    provider=eni.provider.value,
                    account_id=eni.account_id,
                    region=eni.region,
                    relation_type=RelationType.ATTACHED_TO,
                    from_uid=eni.resource_uid,
                    to_uid=subnet_uid
                ))
        
        # Instance attached_to ENI
        instances = assets_by_type.get("ec2.instance", [])
        for instance in instances:
            network_interfaces = instance.metadata.get("network_interfaces", [])
            for ni in network_interfaces:
                if isinstance(ni, dict) and "NetworkInterfaceId" in ni:
                    ni_uid = f"arn:aws:ec2:{instance.region}:{instance.account_id}:network-interface/{ni['NetworkInterfaceId']}"
                    relationships.append(Relationship(
                        tenant_id=self.tenant_id,
                        scan_run_id=self.scan_run_id,
                        provider=instance.provider.value,
                        account_id=instance.account_id,
                        region=instance.region,
                        relation_type=RelationType.ATTACHED_TO,
                        from_uid=instance.resource_uid,
                        to_uid=ni_uid
                    ))
        
        return relationships
    
    def _build_security_relationships(self, assets_by_type: Dict[str, List[Asset]]) -> List[Relationship]:
        """Build security group relationships"""
        relationships = []
        
        # Security group attached_to instance/ENI
        instances = assets_by_type.get("ec2.instance", [])
        for instance in instances:
            security_groups = instance.metadata.get("security_groups", [])
            for sg in security_groups:
                if isinstance(sg, dict) and "GroupId" in sg:
                    sg_uid = f"arn:aws:ec2:{instance.region}:{instance.account_id}:security-group/{sg['GroupId']}"
                    relationships.append(Relationship(
                        tenant_id=self.tenant_id,
                        scan_run_id=self.scan_run_id,
                        provider=instance.provider.value,
                        account_id=instance.account_id,
                        region=instance.region,
                        relation_type=RelationType.ATTACHED_TO,
                        from_uid=instance.resource_uid,
                        to_uid=sg_uid,
                        properties={"direction": "inbound"}
                    ))
        
        return relationships
    
    def _build_internet_exposure(self, assets_by_type: Dict[str, List[Asset]]) -> List[Relationship]:
        """Build internet exposure relationships"""
        relationships = []
        
        # Check for public IPs, public LBs, public buckets
        instances = assets_by_type.get("ec2.instance", [])
        for instance in instances:
            public_ip = instance.metadata.get("public_ip") or instance.metadata.get("PublicIpAddress")
            if public_ip:
                relationships.append(Relationship(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.scan_run_id,
                    provider=instance.provider.value,
                    account_id=instance.account_id,
                    region=instance.region,
                    relation_type=RelationType.INTERNET_CONNECTED,
                    from_uid=instance.resource_uid,
                    to_uid="internet:0.0.0.0/0",
                    properties={"public_ip": public_ip}
                ))
        
        # Public S3 buckets
        buckets = assets_by_type.get("s3.bucket", [])
        for bucket in buckets:
            public_access = bucket.metadata.get("public_access") or bucket.tags.get("Public")
            if public_access:
                relationships.append(Relationship(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.scan_run_id,
                    provider=bucket.provider.value,
                    account_id=bucket.account_id,
                    region=bucket.region,
                    relation_type=RelationType.INTERNET_CONNECTED,
                    from_uid=bucket.resource_uid,
                    to_uid="internet:0.0.0.0/0",
                    properties={"public_access": True}
                ))
        
        return relationships
    
    def _build_identity_relationships(self, assets_by_type: Dict[str, List[Asset]]) -> List[Relationship]:
        """Build IAM identity relationships"""
        relationships = []
        
        # Role attached_to policy
        roles = assets_by_type.get("iam.role", [])
        for role in roles:
            policies = role.metadata.get("attached_policies", [])
            for policy_arn in policies:
                relationships.append(Relationship(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.scan_run_id,
                    provider=role.provider.value,
                    account_id=role.account_id,
                    region=role.region,
                    relation_type=RelationType.ATTACHED_TO,
                    from_uid=role.resource_uid,
                    to_uid=policy_arn
                ))
        
        # User member_of group
        users = assets_by_type.get("iam.user", [])
        for user in users:
            groups = user.metadata.get("groups", [])
            for group_name in groups:
                group_uid = f"arn:aws:iam::{user.account_id}:group/{group_name}"
                relationships.append(Relationship(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.scan_run_id,
                    provider=user.provider.value,
                    account_id=user.account_id,
                    region=user.region,
                    relation_type=RelationType.MEMBER_OF,
                    from_uid=user.resource_uid,
                    to_uid=group_uid
                ))
        
        return relationships
    
    def _build_data_relationships(self, assets_by_type: Dict[str, List[Asset]]) -> List[Relationship]:
        """Build data encryption relationships"""
        relationships = []
        
        # Bucket encrypted_by KMS key
        buckets = assets_by_type.get("s3.bucket", [])
        for bucket in buckets:
            kms_key = bucket.metadata.get("kms_key_id") or bucket.metadata.get("SSEKMSKeyId")
            if kms_key:
                kms_uid = f"arn:aws:kms:{bucket.region}:{bucket.account_id}:key/{kms_key}"
                relationships.append(Relationship(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.scan_run_id,
                    provider=bucket.provider.value,
                    account_id=bucket.account_id,
                    region=bucket.region,
                    relation_type=RelationType.ENCRYPTED_BY,
                    from_uid=bucket.resource_uid,
                    to_uid=kms_uid
                ))
        
        return relationships

