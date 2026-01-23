"""
Database Upload Engine - Upload scan results from NDJSON files to database
"""
import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.database_manager import DatabaseManager
from utils.phase_logger import PhaseLogger

logger = logging.getLogger(__name__)

class DatabaseUploadEngine:
    """Engine for uploading scan results from NDJSON files to database"""
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize database upload engine
        
        Args:
            db_manager: DatabaseManager instance
        """
        self.db = db_manager
        self.phase_logger = None
    
    def upload_scan_to_database(self, scan_id: str, output_dir: Path,
                                customer_id: str, tenant_id: str,
                                provider: str, hierarchy_id: str,
                                hierarchy_type: str) -> Dict[str, Any]:
        """
        Upload all discovery results from NDJSON files to database
        
        Args:
            scan_id: Scan identifier
            output_dir: Output directory containing NDJSON files
            customer_id: Customer identifier
            tenant_id: Tenant identifier
            provider: Provider name (e.g., 'aws')
            hierarchy_id: Hierarchy identifier (e.g., account_id)
            hierarchy_type: Hierarchy type (e.g., 'account')
        
        Returns:
            Dict with upload statistics
        """
        discovery_dir = output_dir / "discovery"
        if not discovery_dir.exists():
            raise FileNotFoundError(f"Discovery directory not found: {discovery_dir}")
        
        # Initialize logger
        self.phase_logger = PhaseLogger(scan_id, "database_upload", output_dir)
        self.phase_logger.info(f"Starting database upload for scan: {scan_id}")
        
        # Find all NDJSON files
        ndjson_files = list(discovery_dir.glob("*_discoveries.ndjson"))
        
        if not ndjson_files:
            self.phase_logger.warning("No NDJSON files found for upload")
            return {
                'total_files': 0,
                'total_records': 0,
                'total_uploaded': 0,
                'errors': []
            }
        
        self.phase_logger.info(f"Found {len(ndjson_files)} NDJSON files to upload")
        
        # Statistics
        stats = {
            'total_files': len(ndjson_files),
            'total_records': 0,
            'total_uploaded': 0,
            'errors': [],
            'by_service': {}
        }
        
        # Process files in parallel
        max_workers = int(os.environ.get('MAX_UPLOAD_WORKERS', '5'))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    self._upload_file,
                    file_path,
                    scan_id,
                    customer_id,
                    tenant_id,
                    provider,
                    hierarchy_id,
                    hierarchy_type
                ): file_path
                for file_path in ndjson_files
            }
            
            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    result = future.result()
                    stats['total_records'] += result['records']
                    stats['total_uploaded'] += result['uploaded']
                    
                    # Track by service
                    service = result.get('service', 'unknown')
                    if service not in stats['by_service']:
                        stats['by_service'][service] = {
                            'records': 0,
                            'uploaded': 0
                        }
                    stats['by_service'][service]['records'] += result['records']
                    stats['by_service'][service]['uploaded'] += result['uploaded']
                    
                    self.phase_logger.info(
                        f"✅ {file_path.name}: {result['uploaded']}/{result['records']} records uploaded"
                    )
                except Exception as e:
                    error_msg = f"Error uploading {file_path.name}: {str(e)}"
                    self.phase_logger.error(error_msg, exc_info=True)
                    stats['errors'].append({
                        'file': str(file_path),
                        'error': str(e)
                    })
        
        # Update scan status
        self.db.update_scan_status(scan_id, 'database_uploaded')
        
        self.phase_logger.info(f"Database upload completed: {stats['total_uploaded']}/{stats['total_records']} records")
        
        return stats
    
    def _upload_file(self, file_path: Path, scan_id: str, customer_id: str,
                     tenant_id: str, provider: str, hierarchy_id: str,
                     hierarchy_type: str) -> Dict[str, Any]:
        """
        Upload a single NDJSON file to database
        
        Args:
            file_path: Path to NDJSON file
            scan_id: Scan identifier
            customer_id: Customer identifier
            tenant_id: Tenant identifier
            provider: Provider name
            hierarchy_id: Hierarchy identifier
            hierarchy_type: Hierarchy type
        
        Returns:
            Dict with upload statistics for this file
        """
        records = []
        
        # Read NDJSON file
        with open(file_path, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        record = json.loads(line)
                        records.append(record)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON in {file_path}: {e}")
                        continue
        
        if not records:
            return {
                'records': 0,
                'uploaded': 0,
                'service': 'unknown'
            }
        
        # Group records by discovery_id for batch processing
        by_discovery = {}
        for record in records:
            discovery_id = record.get('discovery_id')
            if not discovery_id:
                continue
            
            if discovery_id not in by_discovery:
                by_discovery[discovery_id] = []
            
            # Convert record to item format expected by database
            item = {
                'resource_arn': record.get('resource_arn'),
                'resource_id': record.get('resource_id'),
                '_raw_response': record.get('raw_response', {}),
                **record.get('emitted_fields', {})
            }
            
            # Preserve all fields from emitted_fields
            if 'emitted_fields' in record:
                item.update(record['emitted_fields'])
            
            by_discovery[discovery_id].append(item)
        
        # Upload each discovery in batch
        total_uploaded = 0
        service = records[0].get('service', 'unknown') if records else 'unknown'
        region = records[0].get('region') if records else None
        
        for discovery_id, items in by_discovery.items():
            try:
                # Use batch insert
                drift_results = self.db.store_discoveries_batch(
                    scan_id=scan_id,
                    customer_id=customer_id,
                    tenant_id=tenant_id,
                    provider=provider,
                    discovery_id=discovery_id,
                    items=items,
                    hierarchy_id=hierarchy_id,
                    hierarchy_type=hierarchy_type,
                    region=region,
                    service=service
                )
                total_uploaded += len(items)
            except Exception as e:
                logger.error(f"Error uploading discovery {discovery_id}: {e}", exc_info=True)
                raise
        
        return {
            'records': len(records),
            'uploaded': total_uploaded,
            'service': service
        }

