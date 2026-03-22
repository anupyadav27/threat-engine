"""
Common Discovery Engine - CSP-Agnostic Orchestration Layer

Flat-scheduling model:
  1. Enumerate all (service, region) pairs upfront
  2. Pre-load all discovery configs in one batch DB call
  3. Run all pairs through a single asyncio.Semaphore(MAX_CONCURRENT_TASKS)
  4. No nested semaphores — light services finish fast, heavy ones don't block others

This layer is 100% CSP-agnostic. All provider-specific logic is delegated
to the scanner implementation via the DiscoveryScanner interface.
"""

import asyncio
import functools
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging
from concurrent.futures import ThreadPoolExecutor

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent.parent


from common.database.database_manager import DatabaseManager
from common.database.check_db_reader import CheckDBReader
from common.utils.phase_logger import PhaseLogger
from common.utils.progressive_output import ProgressiveOutputWriter
from common.models.provider_interface import DiscoveryScanner, DiscoveryError

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "utils"))
from database_feature_manager import DatabaseFeatureManager

logger = logging.getLogger(__name__)

# AWS services that return identical data across all regions.
AWS_GLOBAL_SERVICES = {
    'controlcatalog', 'savingsplans', 'ce', 'cur',
    'gamelift', 'outposts', 'osis',
    'iam', 'organizations', 'sts', 'route53', 'cloudfront',
    'waf', 'wafv2', 'shield', 'globalaccelerator',
    'importexport', 'support', 'trustedadvisor',
}

# Discovery IDs that return catalog/pricing data, not actual customer resources.
CATALOG_DISCOVERY_IDS = {
    'aws.ec2.describe_instance_type_offerings',
    'aws.ec2.describe_reserved_instances_offerings',
    'aws.ec2.describe_spot_price_history',
    'aws.ec2.describe_fpga_images',
    'aws.ec2.get_vpn_connection_device_types',
    'aws.ec2.describe_id_format',
    'aws.ec2.describe_aggregate_id_format',
    'aws.savingsplans.describe_savings_plans_offerings',
    'aws.savingsplans.describe_savings_plans_offering_rates',
    'aws.gamelift.describe_ec2_instance_limits',
}

PRIMARY_REGIONS = {
    'aws': 'us-east-1', 'azure': 'eastus', 'gcp': 'us-central1',
    'oci': 'us-ashburn-1', 'alicloud': 'cn-hangzhou',
    'ibm': 'us-south', 'k8s': 'cluster',
}

DEFAULT_REGIONS = {
    'aws': ['us-east-1', 'us-west-2', 'eu-west-1'],
    'azure': ['eastus', 'westus2', 'westeurope'],
    'gcp': ['us-central1', 'us-east1', 'europe-west1'],
    'oci': ['us-ashburn-1', 'us-phoenix-1'],
    'alicloud': ['cn-hangzhou', 'cn-shanghai'],
    'ibm': ['us-south', 'us-east', 'eu-de'],
    'k8s': ['cluster'],
}


class DiscoveryEngine:
    """
    CSP-Agnostic Discovery Engine — flat-scheduling model.

    All (service, region) pairs compete for a single concurrency pool.
    No nested semaphores — eliminates head-of-line blocking.
    """

    def __init__(
        self,
        scanner: DiscoveryScanner,
        db_manager: DatabaseManager = None,
        use_database: Optional[bool] = None,
    ):
        self.scanner = scanner
        self.db = db_manager
        self.use_database = self._determine_mode(use_database)

        provider = getattr(scanner, 'provider', 'aws')
        self.feature_manager = DatabaseFeatureManager(provider=provider)
        self.phase_logger = None
        self.output_writer = None

        self.config_source = os.getenv('DISCOVERY_CONFIG_SOURCE', 'database').lower()
        self.check_db_reader = None
        if self.config_source in ('database', 'db', 'yaml_first'):
            try:
                self.check_db_reader = CheckDBReader()
                if self.check_db_reader.check_connection():
                    logger.info(f"CheckDBReader initialized (config_source={self.config_source})")
                else:
                    logger.warning("CheckDBReader connection failed, will use YAML only")
                    self.check_db_reader = None
            except Exception as e:
                logger.warning(f"Failed to initialize CheckDBReader: {e}")
                self.check_db_reader = None

        if self.use_database and not self.db:
            raise ValueError("DatabaseManager required when using database mode")

    def _determine_mode(self, use_database: Optional[bool]) -> bool:
        if use_database is not None:
            return use_database
        env_mode = os.getenv('DISCOVERY_MODE', '').lower()
        if env_mode in ('database', 'db', 'production'):
            return True
        elif env_mode in ('file', 'local', 'ndjson'):
            return False
        if self.db:
            try:
                conn = self.db._get_connection()
                self.db._return_connection(conn)
                return True
            except Exception:
                logger.warning("Database connection failed, using file-only mode")
                return False
        return False

    # ── Main entry point ────────────────────────────────────────────────

    async def run_scan(self, metadata: Dict[str, Any]) -> str:
        """
        Flat-scheduled discovery scan.

        1. Load all service configs in one batch
        2. Build (service, region) work items
        3. Process all via single Semaphore(MAX_CONCURRENT_TASKS)
        """
        scan_id = metadata['scan_run_id']
        provider = metadata['provider']
        customer_id = metadata.get('customer_id', 'default')
        tenant_id = metadata.get('tenant_id', 'default-tenant')
        account_id = metadata['account_id']
        hierarchy_type = metadata.get('hierarchy_type', 'account')
        include_services = metadata.get('include_services')
        include_regions = metadata.get('include_regions')
        exclude_regions = metadata.get('exclude_regions') or []

        # Single concurrency limit for all tasks
        max_concurrent = int(os.getenv('MAX_CONCURRENT_TASKS', '400'))

        # Setup logging
        output_base = os.getenv("OUTPUT_DIR")
        if output_base:
            base_output_dir = Path(output_base)
        else:
            base_output_dir = _project_root() / "engine_output" / f"engine_discoveries_{provider}" / "output"
        output_dir = base_output_dir / "discoveries" / scan_id
        self.phase_logger = PhaseLogger(scan_id, 'discovery', output_dir)
        self.output_writer = ProgressiveOutputWriter(scan_id, output_dir, 'discovery')

        self.phase_logger.info(f"Starting discovery scan: {scan_id}")
        self.phase_logger.info(f"  Provider: {provider}, Hierarchy: {account_id}")

        # ── Step 1: Batch-load all service configs ──────────────────────
        all_configs = self._get_all_configs(provider, include_services)
        if not all_configs:
            self.phase_logger.warning("No services with discovery enabled")
            return scan_id

        services = list(all_configs.keys())
        self.phase_logger.info(f"  Services loaded: {len(services)}")

        # Create scan record
        if self.use_database and self.db:
            self.db.create_scan(
                scan_id=scan_id,
                customer_id=customer_id,
                tenant_id=tenant_id,
                provider=provider,
                account_id=account_id,
                hierarchy_type=hierarchy_type,
            )

        account_id = getattr(self.scanner, 'account_id', None) or account_id

        # ── Step 2: Resolve regions ─────────────────────────────────────
        if include_regions:
            scan_regions = [r for r in include_regions if r not in exclude_regions]
        else:
            scan_regions = await self._discover_available_regions(provider, exclude_regions)
        self.phase_logger.info(f"  Regions: {len(scan_regions)} → {scan_regions}")

        # ── Step 3: Build flat (service, region) work items ─────────────
        primary_region = PRIMARY_REGIONS.get(provider, 'us-east-1')
        work_items: List[Tuple[str, str]] = []
        for service in services:
            config = all_configs[service]
            scope = config.get('scope', 'regional')
            if provider == 'aws' and service in AWS_GLOBAL_SERVICES:
                scope = 'global'
            if scope == 'global':
                work_items.append((service, primary_region))
            else:
                for region in scan_regions:
                    work_items.append((service, region))

        total_tasks = len(work_items)
        self.phase_logger.info(
            f"  Work items: {total_tasks} (flat pool, max_concurrent={max_concurrent})"
        )

        # ── Step 4: Execute all tasks with single semaphore ─────────────
        sem = asyncio.Semaphore(max_concurrent)
        loop = asyncio.get_event_loop()

        # Executor for blocking DB writes
        db_executor = ThreadPoolExecutor(
            max_workers=min(max_concurrent, 30),
            thread_name_prefix='disc-db',
        )

        completed = 0
        total_discoveries = 0
        scan_start = time.time()

        async def run_one(service: str, region: str) -> int:
            nonlocal completed, total_discoveries
            async with sem:
                config = all_configs[service]
                try:
                    result = await self.scanner.scan_service(
                        service=service,
                        region=region,
                        config=config,
                    )
                    discoveries = result[0] if isinstance(result, tuple) else result
                    items = list(discoveries) if discoveries else []
                except Exception as e:
                    logger.error(f"Scan failed: {service}/{region}: {e}")
                    items = []

                count = len(items)

                # Store to DB
                if items and self.use_database and self.db:
                    by_discovery: dict = defaultdict(list)
                    for item in items:
                        if isinstance(item, dict):
                            did = item.pop('_discovery_id', service)
                        else:
                            did = service
                        if did not in CATALOG_DISCOVERY_IDS:
                            by_discovery[did].append(item)

                    store_futures = []
                    for did, group_items in by_discovery.items():
                        store_futures.append(
                            loop.run_in_executor(
                                db_executor,
                                functools.partial(
                                    self.db.store_discoveries_batch,
                                    scan_id=scan_id,
                                    customer_id=customer_id,
                                    tenant_id=tenant_id,
                                    provider=provider,
                                    discovery_id=did,
                                    items=group_items,
                                    account_id=account_id,
                                    hierarchy_type=hierarchy_type,
                                    region=region,
                                    service=service,
                                )
                            )
                        )
                    if store_futures:
                        store_results = await asyncio.gather(*store_futures, return_exceptions=True)
                        for i, r in enumerate(store_results):
                            if isinstance(r, Exception):
                                logger.error(f"DB write failed for {service}/{region}: {r}")

                completed += 1
                total_discoveries += count

                # Progress logging every 50 tasks or when items found
                if count > 0 or completed % 50 == 0 or completed == total_tasks:
                    elapsed = time.time() - scan_start
                    self.phase_logger.info(
                        f"  [{completed}/{total_tasks}] {service}/{region}: "
                        f"{count} items | total={total_discoveries} | {elapsed:.0f}s"
                    )

                return count

        try:
            await asyncio.gather(*[run_one(svc, rgn) for svc, rgn in work_items])
        finally:
            db_executor.shutdown(wait=False)

        # Complete scan
        if self.use_database and self.db:
            self.db.update_scan_status(scan_id, 'completed')

        elapsed = time.time() - scan_start
        self.phase_logger.info(
            f"Discovery scan completed: {total_discoveries} discoveries "
            f"in {elapsed:.0f}s ({total_tasks} tasks, {max_concurrent} concurrent)"
        )

        return scan_id

    # ── Helpers ──────────────────────────────────────────────────────────

    def _get_all_configs(
        self, provider: str, include_services: Optional[List[str]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Batch-load all discovery configs from check DB in one query."""
        if not self.check_db_reader:
            logger.warning("CheckDBReader not available")
            return {}
        try:
            all_configs = self.check_db_reader.read_all_discoveries_configs(provider=provider)
            if include_services:
                all_configs = {k: v for k, v in all_configs.items() if k in include_services}
            return all_configs
        except Exception as e:
            logger.error(f"Failed to load discovery configs: {e}")
            return {}

    async def _discover_available_regions(
        self, provider: str, exclude_regions: List[str] = None
    ) -> List[str]:
        """Pre-scan: enumerate enabled regions from cloud API."""
        try:
            regions = await self.scanner.list_available_regions()
        except Exception as e:
            logger.warning(f"list_available_regions() failed: {e}")
            regions = []

        if not regions:
            regions = DEFAULT_REGIONS.get(provider, ['us-east-1'])
            logger.info(f"Using default regions for {provider}: {regions}")

        if exclude_regions:
            regions = [r for r in regions if r not in exclude_regions]

        return regions
