"""
Common Discovery Engine - CSP-Agnostic Orchestration Layer

This module provides the core orchestration logic for discovery scans across
ALL cloud providers (AWS, Azure, GCP, OCI, AliCloud).

The discovery engine:
1. Gets scan metadata from onboarding DB (scan_orchestration table)
2. Reads discovery configurations from check DB (rule_discoveries table)
3. Calls CSP-specific scanner for actual resource discovery
4. Stores results in discovery_findings table

Parallelism model (3 levels):
  Level 1 — Services:  asyncio.gather with MAX_SERVICE_WORKERS semaphore
  Level 2 — Regions:   asyncio.gather with MAX_REGION_WORKERS semaphore
  Level 3 — API calls: ThreadPoolExecutor inside scan_service() (run_in_executor)

This layer is 100% CSP-agnostic. All provider-specific logic is delegated
to the scanner implementation via the DiscoveryScanner interface.
"""

import asyncio
import os
import sys
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _project_root() -> Path:
    """Repo root (relative to this file)."""
    return Path(__file__).resolve().parent.parent.parent.parent.parent


from common.database.database_manager import DatabaseManager
from common.database.check_db_reader import CheckDBReader
from common.utils.phase_logger import PhaseLogger
from common.utils.progressive_output import ProgressiveOutputWriter
from common.models.provider_interface import DiscoveryScanner, DiscoveryError

# Database-driven feature manager (moved to utils/)
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "utils"))
from database_feature_manager import DatabaseFeatureManager

logger = logging.getLogger(__name__)

# AWS services that return identical data across all regions.
# These are scanned only in the primary region (us-east-1) to avoid
# massive duplication (e.g., controlcatalog: 268K rows → 15K after dedup).
AWS_GLOBAL_SERVICES = {
    'controlcatalog',    # AWS Control Catalog — global control definitions
    'savingsplans',      # Savings Plans offerings — account-level pricing
    'ce',                # Cost Explorer — account-level billing data
    'cur',               # Cost and Usage Reports — account-level
    'gamelift',          # GameLift — returns same offerings across regions
    'outposts',          # Outposts — account-level data
    'osis',              # OpenSearch Ingestion — account-level pipelines
}

# Discovery IDs that return AWS catalog/pricing data, not actual customer resources.
# These inflate finding counts without adding security value.
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


class DiscoveryEngine:
    """
    CSP-Agnostic Discovery Engine

    This engine orchestrates discovery scans across all cloud providers.
    It handles:
    - Reading discovery configs from rule_discoveries table
    - Calling CSP-specific scanners for resource discovery
    - Storing results in discovery_findings table
    - Progress tracking and logging

    The actual cloud API calls are delegated to the CSP-specific scanner
    (AWS, Azure, GCP, OCI, etc.) via the DiscoveryScanner interface.
    """

    def __init__(
        self,
        scanner: DiscoveryScanner,
        db_manager: DatabaseManager = None,
        use_database: Optional[bool] = None
    ):
        """
        Initialize discovery engine

        Args:
            scanner: CSP-specific scanner implementing DiscoveryScanner interface
            db_manager: DatabaseManager instance (optional if using file-only mode)
            use_database: If True, store discoveries in database; If False, files only;
                         If None, auto-detect from environment
        """
        self.scanner = scanner
        self.db = db_manager
        self.use_database = self._determine_mode(use_database)

        # Get provider from scanner
        provider = getattr(scanner, 'provider', 'aws')

        # Use database-driven feature manager
        self.feature_manager = DatabaseFeatureManager(provider=provider)
        self.phase_logger = None
        self.output_writer = None

        # Initialize CheckDBReader for loading discovery configs from database
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
        """Determine whether to use database or file-only mode"""
        if use_database is not None:
            return use_database

        # Auto-detect from environment
        env_mode = os.getenv('DISCOVERY_MODE', '').lower()
        if env_mode in ('database', 'db', 'production'):
            return True
        elif env_mode in ('file', 'local', 'ndjson'):
            return False

        # Default: Use database if connection available, else files only
        if self.db:
            try:
                # Test database connection
                conn = self.db._get_connection()
                self.db._return_connection(conn)
                return True  # Database available, use it
            except Exception:
                logger.warning("Database connection failed, using file-only mode")
                return False

        return False  # Default to file-only for local development

    async def run_scan(self, metadata: Dict[str, Any]) -> str:
        """
        Execute discovery scan using CSP-specific scanner.

        This is the main entry point called by the API server.

        Parallelism:
          - Services run concurrently (MAX_SERVICE_WORKERS, default 10)
          - Regions within each service run concurrently (MAX_REGION_WORKERS, default 5)
          - Sub-discoveries within each region run in thread pool (MAX_DISCOVERY_WORKERS)

        Args:
            metadata: Scan metadata dict with:
                - discovery_scan_id: Unique scan ID
                - orchestration_id: Orchestration ID (optional)
                - provider: CSP name (aws, azure, gcp, oci)
                - customer_id: Customer ID
                - tenant_id: Tenant ID
                - hierarchy_id: Account/subscription/project ID
                - hierarchy_type: account, subscription, project, etc.
                - include_services: List of services to scan (None = all)
                - include_regions: List of regions to scan (None = all)
                - exclude_regions: List of regions to skip (None = none)
                - use_database: Store in database (True/False)

        Returns:
            discovery_scan_id: Unique scan identifier (UUID)
        """
        scan_id = metadata['discovery_scan_id']
        provider = metadata['provider']
        customer_id = metadata.get('customer_id', 'default')
        tenant_id = metadata.get('tenant_id', 'default-tenant')
        hierarchy_id = metadata['hierarchy_id']
        hierarchy_type = metadata.get('hierarchy_type', 'account')
        include_services = metadata.get('include_services')
        include_regions = metadata.get('include_regions')
        exclude_regions = metadata.get('exclude_regions') or []

        # Parallelism config — read from env, safe defaults
        max_service_workers = int(os.getenv('MAX_SERVICE_WORKERS', '10'))
        max_region_workers = int(os.getenv('MAX_REGION_WORKERS', '5'))

        # Setup phase logger and progressive output
        output_base = os.getenv("OUTPUT_DIR")
        if output_base:
            base_output_dir = Path(output_base)
        else:
            base_output_dir = _project_root() / "engine_output" / f"engine_discoveries_{provider}" / "output"

        output_dir = base_output_dir / "discoveries" / scan_id
        self.phase_logger = PhaseLogger(scan_id, 'discovery', output_dir)
        self.output_writer = ProgressiveOutputWriter(scan_id, output_dir, 'discovery')

        self.phase_logger.info(f"Starting discovery scan: {scan_id}")
        self.phase_logger.info(f"  Customer: {customer_id}, Tenant: {tenant_id}")
        self.phase_logger.info(f"  Provider: {provider}")
        self.phase_logger.info(f"  Hierarchy: {hierarchy_id} ({hierarchy_type})")

        # Get enabled services from rule_discoveries table
        services = self._get_enabled_services(provider, include_services)

        if not services:
            self.phase_logger.warning("No services with discovery enabled")
            return scan_id

        self.phase_logger.info(f"  Services to scan: {len(services)}")

        # Create scan record in database
        if self.use_database and self.db:
            self.db.create_scan(
                scan_id=scan_id,
                customer_id=customer_id,
                tenant_id=tenant_id,
                provider=provider,
                hierarchy_id=hierarchy_id,
                hierarchy_type=hierarchy_type,
            )

        # Get account_id from scanner (populated after authenticate())
        account_id = getattr(self.scanner, 'account_id', None) or hierarchy_id

        # Resolve scan regions: explicit > account-discovered > hardcoded fallback
        if include_regions:
            scan_regions = [r for r in include_regions if r not in exclude_regions]
            self.phase_logger.info(f"Using {len(scan_regions)} explicit regions: {scan_regions}")
        else:
            # Pre-scan: discover available regions from the cloud account
            scan_regions = await self._discover_available_regions(provider, exclude_regions)
            self.phase_logger.info(f"Discovered {len(scan_regions)} available regions: {scan_regions}")

        self.phase_logger.info(
            f"Parallelism: {max_service_workers} services × {max_region_workers} regions concurrent"
        )

        # Semaphores to cap concurrency at each level
        service_sem = asyncio.Semaphore(max_service_workers)
        region_sem = asyncio.Semaphore(max_region_workers)

        # Shared counters (thread-safe via asyncio single-thread)
        total_discoveries = 0
        completed_services = 0

        # Dedicated executor for blocking DB operations (config reads, batch stores).
        # Using run_in_executor(None) for these calls prevents them from blocking
        # the asyncio event loop and stalling all other concurrent service scans.
        _db_executor = ThreadPoolExecutor(
            max_workers=max_service_workers * max_region_workers + 4,
            thread_name_prefix='disc-db',
        )

        async def scan_one_service(service: str) -> int:
            """Scan one service across all regions concurrently. Returns discovery count."""
            nonlocal completed_services
            loop = asyncio.get_event_loop()
            async with service_sem:
                try:
                    # _read_discovery_config is a blocking DB/YAML call — run off the
                    # event loop so it doesn't stall other concurrent service scans.
                    import functools
                    config = await loop.run_in_executor(
                        _db_executor,
                        functools.partial(self._read_discovery_config, service, provider),
                    )
                    if not config:
                        self.phase_logger.warning(f"No config for service: {service}")
                        return 0

                    service_discoveries = await self._scan_service_per_region(
                        service=service,
                        config=config,
                        regions=scan_regions,
                        hierarchy_id=hierarchy_id,
                        account_id=account_id,
                        metadata=metadata,
                        region_sem=region_sem,
                    )

                    svc_total = sum(len(v) for v in service_discoveries.values())

                    # Store per-region so region/service/account_id are correct.
                    # store_discoveries_batch is a blocking psycopg2 call — run in
                    # executor to avoid blocking the event loop during DB writes.
                    if self.use_database and self.db:
                        store_tasks = []
                        for region, discoveries in service_discoveries.items():
                            if discoveries:
                                # Group items by their actual per-operation discovery_id
                                by_discovery: dict = defaultdict(list)
                                for item in discoveries:
                                    if isinstance(item, dict):
                                        did = item.pop('_discovery_id', service)
                                    else:
                                        did = service
                                    # Skip catalog/pricing APIs that don't represent real resources
                                    if did in CATALOG_DISCOVERY_IDS:
                                        continue
                                    by_discovery[did].append(item)

                                for did, group_items in by_discovery.items():
                                    store_tasks.append(
                                        loop.run_in_executor(
                                            _db_executor,
                                            functools.partial(
                                                self.db.store_discoveries_batch,
                                                scan_id=scan_id,
                                                customer_id=customer_id,
                                                tenant_id=tenant_id,
                                                provider=provider,
                                                discovery_id=did,
                                                items=group_items,
                                                hierarchy_id=hierarchy_id,
                                                hierarchy_type=hierarchy_type,
                                                account_id=account_id,
                                                region=region,
                                                service=service,
                                            )
                                        )
                                    )
                        if store_tasks:
                            await asyncio.gather(*store_tasks, return_exceptions=True)

                    completed_services += 1
                    self.phase_logger.info(
                        f"  [{completed_services}/{len(services)}] {service}: {svc_total} discoveries"
                    )
                    return svc_total

                except Exception as e:
                    self.phase_logger.error(f"  Service {service} failed: {e}")
                    logger.error(f"Service scan failed: {service}", exc_info=True)
                    return 0

        # Run all services concurrently (bounded by service_sem)
        try:
            results = await asyncio.gather(*[scan_one_service(svc) for svc in services])
        finally:
            # Shut down the DB executor gracefully (non-blocking: don't wait for threads)
            _db_executor.shutdown(wait=False)
        total_discoveries = sum(results)

        # Complete scan
        if self.use_database and self.db:
            self.db.update_scan_status(scan_id, 'completed')

        self.phase_logger.info(f"Discovery scan completed: {total_discoveries} total discoveries")

        return scan_id

    def _get_enabled_services(self, provider: str, include_services: Optional[List[str]] = None) -> List[str]:
        """
        Get list of enabled services from rule_discoveries table.

        Args:
            provider: CSP name (aws, azure, gcp, oci)
            include_services: Optional list to filter services

        Returns:
            List of service names enabled for discovery
        """
        if not self.check_db_reader:
            logger.warning("CheckDBReader not available, cannot get enabled services")
            return include_services or []

        try:
            # Get all services enabled for discovery from rule_discoveries
            all_configs = self.check_db_reader.read_all_discoveries_configs(provider=provider)
            enabled_services = list(all_configs.keys())

            # Filter by include_services if provided
            if include_services:
                enabled_services = [s for s in enabled_services if s in include_services]

            return enabled_services

        except Exception as e:
            logger.error(f"Failed to get enabled services: {e}")
            return include_services or []

    def _read_discovery_config(self, service: str, provider: str) -> Optional[Dict[str, Any]]:
        """
        Read discovery configuration for a service from rule_discoveries table.

        Args:
            service: Service name
            provider: CSP name

        Returns:
            Discovery config dict from rule_discoveries.discoveries_data, or None
        """
        if not self.check_db_reader:
            logger.warning(f"CheckDBReader not available, cannot read config for {service}")
            return None

        try:
            config = self.check_db_reader.read_discoveries_config(service, provider)
            return config

        except Exception as e:
            logger.error(f"Failed to read discovery config for {service}: {e}")
            return None

    async def _scan_service_per_region(
        self,
        service: str,
        config: Dict[str, Any],
        regions: Optional[List[str]],
        hierarchy_id: str,
        account_id: str,
        metadata: Dict[str, Any],
        region_sem: Optional[asyncio.Semaphore] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Execute service discovery across all regions concurrently.

        Regions run concurrently bounded by region_sem.
        Each region's scan_service() call runs in a thread pool executor
        (non-blocking to the asyncio event loop).

        Returns:
            Dict mapping region -> list of discovered resources
        """
        per_region: Dict[str, List[Dict[str, Any]]] = {}
        service_scope = config.get('scope', 'regional')

        # Override: treat known global services as global scope to avoid
        # scanning identical data across all 17 regions (eliminates ~250K dupes)
        if metadata.get('provider', '').lower() == 'aws' and service in AWS_GLOBAL_SERVICES:
            service_scope = 'global'
            logger.info(f"  Service {service} is global — scanning only primary region")

        if service_scope == 'global':
            primary_region = self._get_primary_region(metadata['provider'])
            try:
                result = await self.scanner.scan_service(
                    service=service,
                    region=primary_region,
                    config=config
                )
                discoveries = result[0] if isinstance(result, tuple) else result
                per_region['global'] = list(discoveries)
            except Exception as e:
                raise DiscoveryError(f"Global service {service} scan failed: {e}")

        else:
            scan_regions = regions or self._get_default_regions(metadata['provider'])

            async def scan_one_region(region: str):
                sem = region_sem or asyncio.Semaphore(1)
                async with sem:
                    try:
                        result = await self.scanner.scan_service(
                            service=service,
                            region=region,
                            config=config
                        )
                        discoveries = result[0] if isinstance(result, tuple) else result
                        per_region[region] = list(discoveries)
                    except Exception as e:
                        logger.error(f"Service {service} scan failed in region {region}: {e}")

            await asyncio.gather(*[scan_one_region(r) for r in scan_regions])

        return per_region

    async def _scan_service(
        self,
        service: str,
        config: Dict[str, Any],
        regions: Optional[List[str]],
        hierarchy_id: str,
        metadata: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Legacy: returns flat list (region metadata lost). Use _scan_service_per_region."""
        per_region = await self._scan_service_per_region(
            service=service,
            config=config,
            regions=regions,
            hierarchy_id=hierarchy_id,
            account_id=hierarchy_id,
            metadata=metadata
        )
        return [item for items in per_region.values() for item in items]

    async def _discover_available_regions(
        self, provider: str, exclude_regions: List[str] = None
    ) -> List[str]:
        """
        Pre-scan: enumerate enabled regions for the account from the cloud API.

        For AWS, calls ec2:describe_regions to get all opted-in regions.
        For other CSPs, falls back to hardcoded defaults (scanner returns []).

        Args:
            provider: CSP name (aws, azure, gcp, oci)
            exclude_regions: Optional list of regions to exclude

        Returns:
            Sorted list of region names to scan
        """
        try:
            regions = await self.scanner.list_available_regions()
        except Exception as e:
            logger.warning(f"list_available_regions() failed: {e}")
            regions = []

        if not regions:
            regions = self._get_default_regions(provider)
            logger.info(f"Using hardcoded default regions for {provider}: {regions}")

        if exclude_regions:
            regions = [r for r in regions if r not in exclude_regions]

        return regions

    def _get_primary_region(self, provider: str) -> str:
        """
        Get primary region for global services.

        Args:
            provider: CSP name

        Returns:
            Primary region string
        """
        PRIMARY_REGIONS = {
            'aws': 'us-east-1',
            'azure': 'eastus',
            'gcp': 'us-central1',
            'oci': 'us-ashburn-1',
            'alicloud': 'cn-hangzhou',
            'ibm': 'us-south',
            'k8s': 'cluster',
        }
        return PRIMARY_REGIONS.get(provider, 'us-east-1')

    def _get_default_regions(self, provider: str) -> List[str]:
        """
        Get default regions if none specified.

        Args:
            provider: CSP name

        Returns:
            List of default regions
        """
        DEFAULT_REGIONS = {
            'aws': ['us-east-1', 'us-west-2', 'eu-west-1'],
            'azure': ['eastus', 'westus2', 'westeurope'],
            'gcp': ['us-central1', 'us-east1', 'europe-west1'],
            'oci': ['us-ashburn-1', 'us-phoenix-1'],
            'alicloud': ['cn-hangzhou', 'cn-shanghai'],
            'ibm': ['us-south', 'us-east', 'eu-de'],
            'k8s': ['cluster'],
        }
        return DEFAULT_REGIONS.get(provider, ['us-east-1'])
