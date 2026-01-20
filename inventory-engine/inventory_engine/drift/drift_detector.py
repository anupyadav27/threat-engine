"""
Drift Detector

Compares current scan with previous scan to detect changes.
"""

from typing import List, Dict, Any, Optional
from ..schemas.asset_schema import Asset
from ..schemas.relationship_schema import Relationship
from ..schemas.drift_schema import DriftRecord, ChangeType
import json


class DriftDetector:
    """Detects changes between scan runs"""
    
    def __init__(self, tenant_id: str, current_scan_id: str):
        self.tenant_id = tenant_id
        self.current_scan_id = current_scan_id
    
    def detect_drift(
        self,
        current_assets: List[Asset],
        current_relationships: List[Relationship],
        previous_assets: Optional[List[Asset]] = None,
        previous_relationships: Optional[List[Relationship]] = None
    ) -> List[DriftRecord]:
        """
        Detect drift between current and previous scan.
        
        Returns:
            List of drift records
        """
        drift_records = []
        
        if not previous_assets:
            # First scan - all assets are new
            for asset in current_assets:
                drift_records.append(DriftRecord(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.current_scan_id,
                    change_type=ChangeType.ASSET_ADDED,
                    resource_uid=asset.resource_uid
                ))
            return drift_records
        
        # Build lookup maps
        current_by_uid = {asset.resource_uid: asset for asset in current_assets}
        previous_by_uid = {asset.resource_uid: asset for asset in previous_assets}
        
        current_hashes = {uid: asset.hash_sha256 for uid, asset in current_by_uid.items()}
        previous_hashes = {uid: asset.hash_sha256 for uid, asset in previous_by_uid.items()}
        
        # Detect asset changes
        all_uids = set(current_by_uid.keys()) | set(previous_by_uid.keys())
        
        for uid in all_uids:
            if uid not in previous_by_uid:
                # Asset added
                drift_records.append(DriftRecord(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.current_scan_id,
                    change_type=ChangeType.ASSET_ADDED,
                    resource_uid=uid
                ))
            elif uid not in current_by_uid:
                # Asset removed
                drift_records.append(DriftRecord(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.current_scan_id,
                    change_type=ChangeType.ASSET_REMOVED,
                    resource_uid=uid
                ))
            elif current_hashes.get(uid) != previous_hashes.get(uid):
                # Asset changed
                diff = self._compute_asset_diff(previous_by_uid[uid], current_by_uid[uid])
                drift_records.append(DriftRecord(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.current_scan_id,
                    change_type=ChangeType.ASSET_CHANGED,
                    resource_uid=uid,
                    diff=diff
                ))
        
        # Detect relationship changes
        if previous_relationships:
            current_edges = self._build_edge_set(current_relationships)
            previous_edges = self._build_edge_set(previous_relationships)
            
            # Edges added
            for edge in current_edges - previous_edges:
                drift_records.append(DriftRecord(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.current_scan_id,
                    change_type=ChangeType.EDGE_ADDED,
                    resource_uid=edge  # Edge represented as "from_uid|to_uid|type"
                ))
            
            # Edges removed
            for edge in previous_edges - current_edges:
                drift_records.append(DriftRecord(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.current_scan_id,
                    change_type=ChangeType.EDGE_REMOVED,
                    resource_uid=edge
                ))
        
        return drift_records
    
    def _compute_asset_diff(self, previous: Asset, current: Asset) -> Dict[str, Any]:
        """Compute diff between two assets"""
        diff = []
        
        # Compare tags
        if previous.tags != current.tags:
            for key in set(previous.tags.keys()) | set(current.tags.keys()):
                prev_val = previous.tags.get(key)
                curr_val = current.tags.get(key)
                if prev_val != curr_val:
                    diff.append({
                        "path": f"tags.{key}",
                        "before": prev_val,
                        "after": curr_val
                    })
        
        # Compare metadata (simplified)
        if previous.metadata != current.metadata:
            diff.append({
                "path": "metadata",
                "before": "changed",
                "after": "changed"
            })
        
        return {"changes": diff}
    
    def _build_edge_set(self, relationships: List[Relationship]) -> set:
        """Build set of edge identifiers"""
        edges = set()
        for rel in relationships:
            edge_id = f"{rel.from_uid}|{rel.to_uid}|{rel.relation_type.value}"
            edges.add(edge_id)
        return edges

