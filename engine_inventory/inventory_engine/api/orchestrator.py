"""
Scan Orchestrator

Orchestrates inventory scan execution: collection → normalization → graph → index
"""

import os
import json
import random
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

from ..schemas.asset_schema import Asset, Provider
from ..schemas.relationship_schema import Relationship
from ..schemas.summary_schema import ScanSummary
from ..schemas.drift_schema import DriftRecord
from ..connectors.discovery_reader_factory import get_discovery_reader
from ..connectors.check_db_reader import CheckDBReader
from ..normalizer.asset_normalizer import AssetNormalizer
from ..normalizer.relationship_builder import RelationshipBuilder
from ..drift.drift_detector import DriftDetector
from ..index.index_writer import PostgresIndexWriter


class ScanOrchestrator:
    """Orchestrates inventory scan execution (DB-first)."""
    
    def __init__(
        self,
        tenant_id: str,
        db_url: Optional[str] = None,
    ):
        """
        Initialize Scan Orchestrator.
        
        Args:
            tenant_id: Tenant identifier
            db_url: PostgreSQL database URL (required for DB-first indexing)
        """
        self.tenant_id = tenant_id
        self.db_url = db_url
        # DB-first only: no direct cloud API calls (AWSConnector) and no S3 (boto3).
    
    def run_scan(
        self,
        providers: List[str],
        accounts: List[str],
        regions: List[str],
        services: Optional[List[str]] = None,
        previous_scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run inventory scan (DB-first only).

        This engine no longer calls cloud provider APIs. It derives assets/relationships
        from discoveries stored in the Discoveries DB.
        
        Returns:
            Scan result with scan_run_id and artifact paths
        """
        return self.run_scan_from_discovery(
            discovery_scan_id="latest",
            providers=providers,
            accounts=accounts,
            previous_scan_id=previous_scan_id,
        )
    
    def _save_artifacts(
        self,
        scan_run_id: str,
        assets: List[Asset],
        relationships: List[Relationship],
        drift_records: List[DriftRecord],
        raw_refs: List[str],
        started_at: datetime,
        completed_at: datetime
    ) -> Dict[str, str]:
        """Save normalized artifacts"""
        artifacts = {}
        # DB-first only: write artifacts locally (optional), never to S3.
        from engine_common.storage_paths import get_project_root
        base = os.getenv("INVENTORY_OUTPUT_DIR") or str(get_project_root() / "engine_output" / "engine_inventory" / "output")
        base_path = base
        normalized_dir = os.path.join(base_path, self.tenant_id, scan_run_id, "normalized")
        os.makedirs(normalized_dir, exist_ok=True)
        
        # Save assets.ndjson
        assets_path = os.path.join(normalized_dir, "assets.ndjson")
        with open(assets_path, 'w') as f:
            for asset in assets:
                f.write(json.dumps(asset.dict(), default=str) + "\n")
        artifacts["assets"] = assets_path
        
        # Save relationships.ndjson
        rels_path = os.path.join(normalized_dir, "relationships.ndjson")
        with open(rels_path, 'w') as f:
            for rel in relationships:
                f.write(json.dumps(rel.dict(), default=str) + "\n")
        artifacts["relationships"] = rels_path
        
        # Save summary.json
        summary = self._generate_summary(scan_run_id, assets, relationships, raw_refs, started_at, completed_at)
        summary_path = os.path.join(normalized_dir, "summary.json")
        with open(summary_path, 'w') as f:
            json.dump(summary.dict(), f, default=str)
        artifacts["summary"] = summary_path
        
        # Save drift.ndjson
        if drift_records:
            drift_path = os.path.join(normalized_dir, "drift.ndjson")
            with open(drift_path, 'w') as f:
                for drift in drift_records:
                    f.write(json.dumps(drift.dict(), default=str) + "\n")
            artifacts["drift"] = drift_path
        
        return artifacts
    
    def _generate_summary(
        self,
        scan_run_id: str,
        assets: List[Asset],
        relationships: List[Relationship],
        raw_refs: List[str],
        started_at: datetime,
        completed_at: datetime
    ) -> ScanSummary:
        """Generate scan summary"""
        from ..schemas.summary_schema import ScanSummary
        
        # Count by provider
        assets_by_provider = {}
        for asset in assets:
            provider = asset.provider.value
            assets_by_provider[provider] = assets_by_provider.get(provider, 0) + 1
        
        # Count by resource type
        assets_by_resource_type = {}
        for asset in assets:
            rtype = asset.resource_type
            assets_by_resource_type[rtype] = assets_by_resource_type.get(rtype, 0) + 1
        
        # Count by region
        assets_by_region = {}
        for asset in assets:
            region = asset.region
            assets_by_region[region] = assets_by_region.get(region, 0) + 1
        
        # Extract unique providers, accounts, regions
        providers_scanned = list(set(asset.provider.value for asset in assets))
        accounts_scanned = list(set(asset.account_id for asset in assets))
        regions_scanned = list(set(asset.region for asset in assets))
        
        return ScanSummary(
            scan_run_id=scan_run_id,
            tenant_id=self.tenant_id,
            started_at=started_at,
            completed_at=completed_at,
            status="completed",
            total_assets=len(assets),
            total_relationships=len(relationships),
            assets_by_provider=assets_by_provider,
            assets_by_resource_type=assets_by_resource_type,
            assets_by_region=assets_by_region,
            providers_scanned=providers_scanned,
            accounts_scanned=accounts_scanned,
            regions_scanned=regions_scanned,
            errors_count=0,
            raw_refs=raw_refs
        )
    
    def _load_previous_scan(self, previous_scan_id: str) -> tuple[List[Asset], List[Relationship]]:
        """Load previous scan assets and relationships"""
        # TODO: Implement loading from S3/local
        return [], []
    
    def run_scan_from_discovery(
        self,
        discovery_scan_id: str,
        check_scan_id: Optional[str] = None,
        providers: Optional[List[str]] = None,
        accounts: Optional[List[str]] = None,
        previous_scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run inventory scan from discovery output (DB-first).
        
        Args:
            discovery_scan_id: Discovery scan ID (or "latest")
            providers: Optional filter by providers
            accounts: Optional filter by accounts
            previous_scan_id: Optional previous scan for drift detection
        
        Returns:
            Scan result with scan_run_id and artifact paths
        """
        scan_run_id = f"inv_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000,9999)}"
        started_at = datetime.utcnow()
        
        # Step 1: Read discovery records using factory (supports local files or database)
        discovery_reader = get_discovery_reader(tenant_id=self.tenant_id)
        all_assets = []
        raw_refs = []
        seen_resources = set()  # Track unique resources to avoid duplicates
        
        # Read all discovery records
        for discovery_record in discovery_reader.read_discovery_records(discovery_scan_id):
            provider_str = discovery_record.get("provider", "aws")
            account_id = discovery_record.get("account_id") or discovery_record.get("hierarchy_id")
            if account_id and not discovery_record.get("account_id"):
                # Normalize DB reader shape to what the normalizers expect.
                discovery_record["account_id"] = account_id
            
            # Apply filters
            if providers and provider_str not in providers:
                continue
            if accounts and account_id not in accounts:
                continue
            
            # Normalize discovery record to asset
            normalizer = AssetNormalizer(self.tenant_id, scan_run_id)
            raw_ref = f"discovery:{discovery_scan_id}:{discovery_record.get('discovery_id', 'unknown')}"
            
            asset = normalizer.normalize_from_discovery(discovery_record, raw_ref)
            if asset:
                # Deduplicate by resource_uid
                if asset.resource_uid not in seen_resources:
                    all_assets.append(asset)
                    seen_resources.add(asset.resource_uid)
                    raw_refs.append(raw_ref)
        logger.info(f"[{scan_run_id}] Loaded {len(all_assets)} unique assets from discoveries (scan_id={discovery_scan_id})")

        # Optional: enrich assets with check posture from Check DB
        if check_scan_id:
            try:
                posture = CheckDBReader().get_posture_by_resource(
                    scan_id=check_scan_id,
                    tenant_id=self.tenant_id,
                )
                enriched = 0
                for asset in all_assets:
                    uid = asset.resource_uid
                    if uid and uid in posture:
                        asset.metadata = asset.metadata or {}
                        asset.metadata["check_posture"] = posture[uid]
                        enriched += 1
                logger.info(f"[{scan_run_id}] Enriched {enriched} assets with check posture (check_scan_id={check_scan_id})")
            except Exception as e:
                logger.warning(f"[{scan_run_id}] Failed to enrich assets with check posture: {e}")
        
        # Step 2: Build relationships
        relationship_builder = RelationshipBuilder(self.tenant_id, scan_run_id)
        all_relationships = relationship_builder.build_relationships(all_assets)
        
        # Step 3: Detect drift (if previous scan provided)
        drift_records = []
        if previous_scan_id:
            previous_assets, previous_relationships = self._load_previous_scan(previous_scan_id)
            drift_detector = DriftDetector(self.tenant_id, scan_run_id)
            drift_records = drift_detector.detect_drift(
                all_assets, all_relationships,
                previous_assets, previous_relationships
            )
        
        # Step 4: Save normalized artifacts
        completed_at = datetime.utcnow()
        artifact_paths = self._save_artifacts(
            scan_run_id, all_assets, all_relationships, drift_records, raw_refs, started_at, completed_at
        )
        
        # Step 5: Write indexes (DB-first output)
        if self.db_url:
            summary = self._generate_summary(
                scan_run_id, all_assets, all_relationships, raw_refs, started_at, completed_at
            )
            index_writer = PostgresIndexWriter(self.db_url)
            index_writer.write_scan_summary(summary)
            index_writer.write_asset_index(all_assets)
            index_writer.write_relationship_index(all_relationships)
        
        return {
            "scan_run_id": scan_run_id,
            "status": "completed",
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "total_assets": len(all_assets),
            "total_relationships": len(all_relationships),
            "total_drift": len(drift_records),
            "artifact_paths": artifact_paths
        }

