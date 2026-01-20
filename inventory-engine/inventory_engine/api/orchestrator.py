"""
Scan Orchestrator

Orchestrates inventory scan execution: collection → normalization → graph → index
"""

import os
import json
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
import boto3

from ..schemas.asset_schema import Asset, Provider
from ..schemas.relationship_schema import Relationship
from ..schemas.summary_schema import ScanSummary
from ..schemas.drift_schema import DriftRecord
from ..connectors.aws_connector import AWSConnector
from ..normalizer.asset_normalizer import AssetNormalizer
from ..normalizer.relationship_builder import RelationshipBuilder
from ..drift.drift_detector import DriftDetector
from ..graph.neo4j_loader import Neo4jGraphLoader
from ..index.index_writer import PostgresIndexWriter


class ScanOrchestrator:
    """Orchestrates inventory scan execution"""
    
    def __init__(
        self,
        tenant_id: str,
        s3_bucket: str = "cspm-lgtech",
        db_url: Optional[str] = None,
        neo4j_uri: Optional[str] = None,
        neo4j_username: Optional[str] = None,
        neo4j_password: Optional[str] = None
    ):
        self.tenant_id = tenant_id
        self.s3_bucket = s3_bucket
        self.db_url = db_url
        self.neo4j_uri = neo4j_uri
        self.neo4j_username = neo4j_username
        self.neo4j_password = neo4j_password
        
        self.s3_client = boto3.client('s3') if os.getenv("USE_S3", "false").lower() == "true" else None
    
    def run_scan(
        self,
        providers: List[str],
        accounts: List[str],
        regions: List[str],
        services: Optional[List[str]] = None,
        previous_scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run complete inventory scan.
        
        Returns:
            Scan result with scan_run_id and artifact paths
        """
        scan_run_id = f"inv_{uuid.uuid4().hex[:12]}"
        started_at = datetime.utcnow()
        
        # Step 1: Collect raw resources
        raw_refs = []
        all_assets = []
        all_relationships = []
        
        for provider in providers:
            provider_enum = Provider(provider.lower())
            
            if provider_enum == Provider.AWS:
                connector = AWSConnector()
                for account_id in accounts:
                    for region in regions:
                        # Collect from each service
                        service_list = services or ["s3", "ec2", "iam", "rds"]
                        for service in service_list:
                            raw_data = connector.collect_service_resources(
                                service, account_id, region
                            )
                            
                            # Save raw data to S3/local
                            raw_ref = self._save_raw_data(
                                scan_run_id, provider, account_id, region, service, raw_data
                            )
                            raw_refs.append(raw_ref)
                            
                            # Normalize to assets
                            normalizer = AssetNormalizer(self.tenant_id, scan_run_id)
                            assets = normalizer.normalize_from_raw(
                                raw_data, provider_enum, account_id, region, service, raw_ref
                            )
                            all_assets.extend(assets)
        
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
        
        # Step 5: Load into Neo4j (if configured)
        if self.neo4j_uri:
            graph_loader = Neo4jGraphLoader(
                self.neo4j_uri, self.neo4j_username or "", self.neo4j_password or ""
            )
            graph_loader.load_assets(all_assets, scan_run_id)
            graph_loader.load_relationships(all_relationships)
            graph_loader.close()
        
        # Step 6: Write indexes (if DB configured)
        if self.db_url:
            summary = self._generate_summary(
                scan_run_id, all_assets, all_relationships, raw_refs, started_at, completed_at
            )
            index_writer = PostgresIndexWriter(self.db_url)
            index_writer.write_scan_summary(summary)
            index_writer.write_asset_index(all_assets)
        
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
    
    def _save_raw_data(
        self,
        scan_run_id: str,
        provider: str,
        account_id: str,
        region: str,
        service: str,
        data: Dict[str, Any]
    ) -> str:
        """Save raw collector output"""
        if self.s3_client:
            key = f"inventory/{self.tenant_id}/{scan_run_id}/raw/{provider}/{account_id}/{region}/{service}.json"
            self.s3_client.put_object(
                Bucket=self.s3_bucket,
                Key=key,
                Body=json.dumps(data, default=str)
            )
            return f"s3://{self.s3_bucket}/{key}"
        else:
            # Local storage
            base_path = os.getenv("INVENTORY_OUTPUT_DIR", "/Users/apple/Desktop/threat-engine/engines-output/inventory-engine/output")
            file_path = os.path.join(base_path, self.tenant_id, scan_run_id, "raw", provider, account_id, region, f"{service}.json")
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                json.dump(data, f, default=str)
            return file_path
    
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
        
        if self.s3_client:
            base_prefix = f"inventory/{self.tenant_id}/{scan_run_id}/normalized"
            
            # Save assets.ndjson
            assets_key = f"{base_prefix}/assets.ndjson"
            assets_body = "\n".join([json.dumps(asset.dict(), default=str) for asset in assets])
            self.s3_client.put_object(Bucket=self.s3_bucket, Key=assets_key, Body=assets_body)
            artifacts["assets"] = f"s3://{self.s3_bucket}/{assets_key}"
            
            # Save relationships.ndjson
            rels_key = f"{base_prefix}/relationships.ndjson"
            rels_body = "\n".join([json.dumps(rel.dict(), default=str) for rel in relationships])
            self.s3_client.put_object(Bucket=self.s3_bucket, Key=rels_key, Body=rels_body)
            artifacts["relationships"] = f"s3://{self.s3_bucket}/{rels_key}"
            
            # Save summary.json
            summary = self._generate_summary(scan_run_id, assets, relationships, raw_refs, started_at, completed_at)
            summary_key = f"{base_prefix}/summary.json"
            self.s3_client.put_object(Bucket=self.s3_bucket, Key=summary_key, Body=json.dumps(summary.dict(), default=str))
            artifacts["summary"] = f"s3://{self.s3_bucket}/{summary_key}"
            
            # Save drift.ndjson (if any)
            if drift_records:
                drift_key = f"{base_prefix}/drift.ndjson"
                drift_body = "\n".join([json.dumps(drift.dict(), default=str) for drift in drift_records])
                self.s3_client.put_object(Bucket=self.s3_bucket, Key=drift_key, Body=drift_body)
                artifacts["drift"] = f"s3://{self.s3_bucket}/{drift_key}"
        else:
            # Local storage
            base_path = os.getenv("INVENTORY_OUTPUT_DIR", "/Users/apple/Desktop/threat-engine/engines-output/inventory-engine/output")
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

