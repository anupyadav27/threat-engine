"""
Common Discovery Engine - CSP-Agnostic Orchestration Layer

Scan-then-upload model with org-wide multi-account support:

  Phase 0 — ORG ACCOUNTS (optional)
    If SCAN_ORG_ENABLED=true, enumerate all accounts via scanner.list_org_accounts().
    Each account gets its own cloned scanner (assumed role).
    Otherwise behaves as single-account mode.

  Phase 1 — SCAN (per account, global + regional pools in parallel)
    For each account two separate asyncio.Semaphore pools run concurrently:
      • Global pool  (MAX_GLOBAL_CONCURRENT, default 50)
          – IAM, Route53, CloudFront, WAF, ... scanned ONCE in primary region
          – These are fast — many can run in parallel without thrashing
      • Regional pool  (MAX_REGIONAL_CONCURRENT, default 400)
          – EC2, RDS, S3, Lambda, ... scanned in EVERY enabled region
          – Heavier calls — bounded separately so they don't starve global scans

    All accounts scan simultaneously, bounded by MAX_ACCOUNTS_CONCURRENT (default 10).
    Results are kept in memory — NO DB writes during Phase 1.

  Phase 1b — PERSIST scan attempt metadata (service_scan_attempts)

  Phase 2 — UPLOAD (bulk write, per account, sequential)
    DiscoveryUploader writes per-account results to discovery_findings.

Key env vars
────────────
  SCAN_ORG_ENABLED        true | false (default false)
  ORG_ROLE_NAME           IAM role to assume in each org account (default ThreatEngineScanRole)
  MAX_ACCOUNTS_CONCURRENT Max accounts scanned in parallel         (default 10)
  MAX_GLOBAL_CONCURRENT   Semaphore for global service pool         (default 50)
  MAX_REGIONAL_CONCURRENT Semaphore for regional service pool       (default 400)
  SERVICE_SCAN_TIMEOUT    Per-service timeout seconds               (default 120)
  SCAN_THREAD_POOL        ThreadPoolExecutor size                   (default 500)
"""

import asyncio
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent.parent


from common.database.database_manager import DatabaseManager
from common.database.check_db_reader import CheckDBReader
from common.storage.discovery_uploader import DiscoveryUploader
from common.utils.phase_logger import PhaseLogger
from common.utils.progressive_output import ProgressiveOutputWriter
from common.models.provider_interface import DiscoveryScanner, DiscoveryError

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "utils"))
from database_feature_manager import DatabaseFeatureManager

logger = logging.getLogger(__name__)

# AWS services that return identical data across all regions — scan once in primary_region.
AWS_GLOBAL_SERVICES = {
    'controlcatalog', 'savingsplans', 'ce', 'cur',
    'gamelift', 'outposts', 'osis',
    'iam', 'organizations', 'sts', 'route53', 'cloudfront',
    'waf', 'wafv2', 'shield', 'globalaccelerator',
    'importexport', 'support', 'trustedadvisor',
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


class ScanTimer:
    """
    Collects per-account, per-pool, and per-service timing data.

    All wall-clock times are stored as UTC ISO-8601 strings so they are
    readable in pod logs, Argo UI, and JSONB DB columns.

    Structure produced by .report():
    {
      "scan_run_id": "...",
      "scan_start":  "2026-04-22T10:00:00Z",
      "scan_end":    "2026-04-22T10:45:00Z",
      "total_s":     2700,
      "phase1_s":    2680,
      "phase2_s":    20,
      "accounts": {
        "123456789012": {
          "account_start":  "...",
          "account_end":    "...",
          "account_s":      2680,
          "global_pool": {
            "start_s":    0.0,    # seconds offset from account_start
            "end_s":      45.2,
            "elapsed_s":  45.2,
            "services":   20,
            "discoveries":1250,
            "slowest": [          # top-5 slowest (service, region, duration_ms, discoveries)
              {"service": "iam", "region": "us-east-1", "duration_ms": 12400, "discoveries": 890},
              ...
            ]
          },
          "regional_pool": {
            "start_s":    0.1,
            "end_s":      2680.0,
            "elapsed_s":  2679.9,
            "services":   360,
            "regions":    20,
            "work_items": 7200,
            "discoveries":15000,
            "slowest": [...]
          }
        }
      },
      "totals": {
        "accounts":   1,
        "services":   380,
        "regions":    20,
        "work_items": 7220,
        "discoveries":16250
      }
    }
    """

    def __init__(self, scan_run_id: str):
        self.scan_run_id = scan_run_id
        self._scan_start = time.monotonic()
        self._scan_wall = datetime.now(timezone.utc)
        self._phase1_end: Optional[float] = None
        self._phase2_start: Optional[float] = None
        self._phase2_end: Optional[float] = None
        # per account: {account_id: {...}}
        self._accounts: Dict[str, Dict[str, Any]] = {}

    # ── account lifecycle ────────────────────────────────────────────────

    def account_start(self, account_id: str) -> None:
        self._accounts[account_id] = {
            '_start': time.monotonic(),
            '_wall': datetime.now(timezone.utc),
            'global': None,
            'regional': None,
            '_meta': [],   # list of scan_meta dicts from scan_one
        }

    def account_end(self, account_id: str) -> None:
        a = self._accounts.get(account_id)
        if a:
            a['_end'] = time.monotonic()

    # ── pool lifecycle ───────────────────────────────────────────────────

    def pool_start(self, account_id: str, pool: str) -> None:
        """pool: 'global' or 'regional'"""
        a = self._accounts.get(account_id, {})
        a[f'_{pool}_start'] = time.monotonic()

    def pool_end(self, account_id: str, pool: str) -> None:
        a = self._accounts.get(account_id, {})
        a[f'_{pool}_end'] = time.monotonic()

    # ── per-service metadata ─────────────────────────────────────────────

    def record_service(self, account_id: str, meta: Dict[str, Any]) -> None:
        """Call after each scan_one completes with its scan_meta dict."""
        a = self._accounts.get(account_id)
        if a is not None:
            a['_meta'].append(meta)

    # ── phase markers ────────────────────────────────────────────────────

    def phase1_done(self) -> None:
        self._phase1_end = time.monotonic()

    def phase2_start(self) -> None:
        self._phase2_start = time.monotonic()

    def phase2_done(self) -> None:
        self._phase2_end = time.monotonic()

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _top_slowest(meta_list: List[Dict], n: int = 5) -> List[Dict]:
        return sorted(
            [
                {
                    'service': m.get('service', '?'),
                    'region':  m.get('region',  '?'),
                    'duration_ms': m.get('duration_ms', 0),
                    'discoveries': m.get('discoveries', 0),
                    'status': m.get('status', '?'),
                }
                for m in meta_list
                if m.get('status') not in ('unavailable',)
            ],
            key=lambda x: x['duration_ms'],
            reverse=True,
        )[:n]

    @staticmethod
    def _pool_meta(meta_list: List[Dict], pool_services: List[str]) -> Dict:
        pool_set = set(pool_services)
        return [m for m in meta_list if m.get('service') in pool_set]

    def _elapsed(self, t0: Optional[float], t1: Optional[float]) -> Optional[float]:
        if t0 is None or t1 is None:
            return None
        return round(t1 - t0, 1)

    # ── public report ────────────────────────────────────────────────────

    def report(
        self,
        global_services: List[str],
        regional_services: List[str],
        scan_regions: List[str],
    ) -> Dict[str, Any]:
        now = time.monotonic()
        scan_end_wall = datetime.now(timezone.utc)
        total_s = round(now - self._scan_start, 1)
        phase1_s = self._elapsed(self._scan_start, self._phase1_end)
        phase2_s = self._elapsed(self._phase2_start, self._phase2_end)

        accounts_out = {}
        grand_discoveries = 0

        for acct_id, a in self._accounts.items():
            acct_start = a['_start']
            acct_end   = a.get('_end', now)
            acct_wall  = a['_wall']
            meta_all   = a.get('_meta', [])

            g_start = a.get('_global_start')
            g_end   = a.get('_global_end')
            r_start = a.get('_regional_start')
            r_end   = a.get('_regional_end')

            g_meta = self._pool_meta(meta_all, global_services)
            r_meta = self._pool_meta(meta_all, regional_services)

            g_disc = sum(m.get('discoveries', 0) for m in g_meta)
            r_disc = sum(m.get('discoveries', 0) for m in r_meta)
            grand_discoveries += g_disc + r_disc

            accounts_out[acct_id] = {
                'account_start': acct_wall.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'account_s': round(acct_end - acct_start, 1),
                'global_pool': {
                    'start_offset_s': round(g_start - acct_start, 1) if g_start else None,
                    'elapsed_s': self._elapsed(g_start, g_end),
                    'services': len(global_services),
                    'discoveries': g_disc,
                    'slowest_top5': self._top_slowest(g_meta),
                },
                'regional_pool': {
                    'start_offset_s': round(r_start - acct_start, 1) if r_start else None,
                    'elapsed_s': self._elapsed(r_start, r_end),
                    'services': len(regional_services),
                    'regions': len(scan_regions),
                    'work_items': len(regional_services) * len(scan_regions),
                    'discoveries': r_disc,
                    'slowest_top5': self._top_slowest(r_meta),
                },
            }

        rpt = {
            'scan_run_id': self.scan_run_id,
            'scan_start':  self._scan_wall.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'scan_end':    scan_end_wall.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'total_s':     total_s,
            'phase1_scan_s':   phase1_s,
            'phase2_upload_s': phase2_s,
            'accounts': accounts_out,
            'totals': {
                'accounts':    len(self._accounts),
                'global_services': len(global_services),
                'regional_services': len(regional_services),
                'regions':     len(scan_regions),
                'work_items_per_account': len(global_services) + len(regional_services) * len(scan_regions),
                'total_discoveries': grand_discoveries,
            },
        }
        return rpt

    def log_summary(
        self,
        logger_fn,
        global_services: List[str],
        regional_services: List[str],
        scan_regions: List[str],
    ) -> None:
        """Print a human-readable timing summary to the supplied logger function."""
        rpt = self.report(global_services, regional_services, scan_regions)

        logger_fn("=" * 72)
        logger_fn("SCAN TIMING REPORT")
        logger_fn(f"  scan_run_id  : {rpt['scan_run_id']}")
        logger_fn(f"  start        : {rpt['scan_start']}")
        logger_fn(f"  end          : {rpt['scan_end']}")
        logger_fn(f"  total        : {rpt['total_s']}s")
        logger_fn(f"  phase1 scan  : {rpt['phase1_scan_s']}s")
        logger_fn(f"  phase2 upload: {rpt['phase2_upload_s']}s")
        t = rpt['totals']
        logger_fn(
            f"  totals       : {t['accounts']} accounts | "
            f"{t['global_services']} global svcs | "
            f"{t['regional_services']} regional svcs × {t['regions']} regions | "
            f"{t['total_discoveries']} resources"
        )
        logger_fn("-" * 72)
        for acct_id, a in rpt['accounts'].items():
            gp = a['global_pool']
            rp = a['regional_pool']
            logger_fn(f"  ACCOUNT {acct_id}  total={a['account_s']}s")
            logger_fn(
                f"    global  pool: {gp['elapsed_s']}s | "
                f"{gp['services']} svcs | {gp['discoveries']} resources"
            )
            if gp['slowest_top5']:
                for s in gp['slowest_top5'][:3]:
                    logger_fn(
                        f"      slow: {s['service']:20s} {s['duration_ms']:6d}ms  "
                        f"{s['discoveries']} resources [{s['status']}]"
                    )
            logger_fn(
                f"    regional pool: {rp['elapsed_s']}s | "
                f"{rp['services']} svcs × {rp['regions']} regions = "
                f"{rp['work_items']} items | {rp['discoveries']} resources"
            )
            if rp['slowest_top5']:
                for s in rp['slowest_top5'][:5]:
                    logger_fn(
                        f"      slow: {s['service']:20s}/{s['region']:15s} "
                        f"{s['duration_ms']:6d}ms  {s['discoveries']} resources [{s['status']}]"
                    )
        logger_fn("=" * 72)
        # Also emit as one-line JSON for easy log grep/parsing
        logger_fn(f"TIMING_JSON: {json.dumps(rpt)}")


class DiscoveryEngine:
    """
    CSP-Agnostic Discovery Engine.

    Supports:
    - Single-account mode (default): scans the account from scan metadata
    - Org-wide mode (SCAN_ORG_ENABLED=true): enumerates all org accounts,
      clones a scanner per account, scans all accounts in parallel

    Within each account, global and regional services run in two separate
    semaphore pools concurrently — global scans never wait behind regional ones.
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

    # ── Main entry point ────────────────────────────────────────────────────

    async def run_scan(self, metadata: Dict[str, Any]) -> str:
        scan_id = metadata['scan_run_id']
        provider = metadata['provider']
        customer_id = metadata.get('customer_id') or 'default'
        tenant_id = metadata.get('tenant_id') or 'default-tenant'
        account_id = metadata['account_id']
        hierarchy_type = metadata.get('hierarchy_type', 'account')
        include_services = metadata.get('include_services')
        include_regions = metadata.get('include_regions')
        exclude_regions = metadata.get('exclude_regions') or []

        output_base = os.getenv("OUTPUT_DIR")
        if output_base:
            base_output_dir = Path(output_base)
        else:
            base_output_dir = _project_root() / "engine_output" / f"engine_discoveries_{provider}" / "output"
        output_dir = base_output_dir / "discoveries" / scan_id
        self.phase_logger = PhaseLogger(scan_id, 'discovery', output_dir)
        self.output_writer = ProgressiveOutputWriter(scan_id, output_dir, 'discovery')

        self.phase_logger.info(f"Starting discovery scan: {scan_id}")
        self.phase_logger.info(f"  Provider: {provider}, Root account: {account_id}")

        try:
            return await self._execute_scan(
                scan_id=scan_id,
                provider=provider,
                customer_id=customer_id,
                tenant_id=tenant_id,
                root_account_id=account_id,
                hierarchy_type=hierarchy_type,
                include_services=include_services,
                include_regions=include_regions,
                exclude_regions=exclude_regions,
            )
        except Exception as e:
            self.phase_logger.error(f"Discovery scan failed: {e}")
            if self.use_database and self.db:
                self.db.update_scan_status(scan_id, 'failed')
            raise

    # ── Core scan logic ─────────────────────────────────────────────────────

    async def _execute_scan(
        self,
        scan_id: str,
        provider: str,
        customer_id: str,
        tenant_id: str,
        root_account_id: str,
        hierarchy_type: str,
        include_services: Optional[List[str]],
        include_regions: Optional[List[str]],
        exclude_regions: List[str],
    ) -> str:
        scan_start = time.time()
        timer = ScanTimer(scan_id)

        # ── Step 1: Batch-load all service configs ───────────────────────────
        all_configs = self._get_all_configs(provider, include_services)
        if not all_configs:
            self.phase_logger.warning("No services with discovery enabled")
            if self.use_database and self.db:
                self.db.update_scan_status(scan_id, 'completed')
            return scan_id

        services = list(all_configs.keys())
        check_services = self._get_check_services(provider)
        self.phase_logger.info(
            f"  Services loaded: {len(services)} "
            f"({sum(1 for s in services if s in check_services)} with check rules, "
            f"{sum(1 for s in services if s not in check_services)} asset-only)"
        )

        # Create top-level scan record
        if self.use_database and self.db:
            self.db.create_scan(
                scan_id=scan_id, customer_id=customer_id, tenant_id=tenant_id,
                provider=provider, account_id=root_account_id, hierarchy_type=hierarchy_type,
            )

        # ── Step 2: Resolve shared regions (from root account) ──────────────
        if include_regions:
            scan_regions = [r for r in include_regions if r not in exclude_regions]
        else:
            scan_regions = await self._discover_available_regions(provider, exclude_regions)
        self.phase_logger.info(f"  Regions ({len(scan_regions)}): {scan_regions}")

        # ── Step 3: Classify services into global vs regional ────────────────
        primary_region = PRIMARY_REGIONS.get(provider, 'us-east-1')
        global_services: List[str] = []
        regional_services: List[str] = []
        for svc in services:
            cfg = all_configs[svc]
            scope = cfg.get('scope', 'regional')
            if provider == 'aws' and svc in AWS_GLOBAL_SERVICES:
                scope = 'global'
            if scope == 'global':
                global_services.append(svc)
            else:
                regional_services.append(svc)

        self.phase_logger.info(
            f"  Global services: {len(global_services)} | "
            f"Regional services: {len(regional_services)} × {len(scan_regions)} regions = "
            f"{len(regional_services) * len(scan_regions)} work items"
        )

        # ── Step 4: Org account enumeration ─────────────────────────────────
        org_accounts = await self._enumerate_org_accounts(root_account_id)
        self.phase_logger.info(f"  Accounts to scan: {len(org_accounts)}")

        # ── Step 5: Concurrency settings ────────────────────────────────────
        max_global = int(os.getenv('MAX_GLOBAL_CONCURRENT', '50'))
        max_regional = int(os.getenv('MAX_REGIONAL_CONCURRENT', '400'))
        max_accounts = int(os.getenv('MAX_ACCOUNTS_CONCURRENT', '10'))
        service_timeout = int(os.getenv('SERVICE_SCAN_TIMEOUT', '120'))

        # Single shared semaphores — all accounts compete for the same pool.
        # This prevents 10 accounts × 400 workers = 4000 goroutines.
        global_sem = asyncio.Semaphore(max_global)
        regional_sem = asyncio.Semaphore(max_regional)
        account_sem = asyncio.Semaphore(max_accounts)

        # ThreadPool: global + regional concurrency + buffer for account-level work
        thread_pool_size = max_global + max_regional + max_accounts + 10
        scan_executor = ThreadPoolExecutor(
            max_workers=int(os.getenv('SCAN_THREAD_POOL', str(thread_pool_size))),
            thread_name_prefix='disc-scan',
        )
        loop = asyncio.get_event_loop()
        loop.set_default_executor(scan_executor)

        # ── Phase 1: SCAN — per-account results collected in memory ─────────
        # Structure: {account_id: {(service, region): [items]}}
        all_account_results: Dict[str, Dict[Tuple[str, str], List[Dict[str, Any]]]] = {}
        all_account_metadata: Dict[str, List[Dict[str, Any]]] = {}

        # Thread-safe totals for progress logging
        total_discovered = 0
        completed_tasks = 0
        total_tasks = len(org_accounts) * (
            len(global_services) + len(regional_services) * len(scan_regions)
        )

        async def scan_one(
            acct_scanner: DiscoveryScanner,
            account_id: str,
            service: str,
            region: str,
            sem: asyncio.Semaphore,
            acct_results: Dict[Tuple[str, str], List[Dict[str, Any]]],
            acct_meta: List[Dict[str, Any]],
            results_lock: asyncio.Lock,
            meta_lock: asyncio.Lock,
        ) -> int:
            """Scan one (service, region) pair — NO DB writes."""
            nonlocal total_discovered, completed_tasks
            task_start = time.time()
            scan_meta: Dict[str, Any] = {
                'service': service, 'region': region,
                'status': 'failed', 'discoveries': 0,
                'error': None, 'error_message': None,
            }
            async with sem:
                config = all_configs[service]
                items = []
                try:
                    needs_dependents = (not check_services) or (service in check_services)
                    task = asyncio.ensure_future(
                        acct_scanner.scan_service(
                            service=service,
                            region=region,
                            config=config,
                            skip_dependents=not needs_dependents,
                        )
                    )
                    done, _ = await asyncio.wait({task}, timeout=service_timeout)
                    if done:
                        result = task.result()
                        if isinstance(result, tuple):
                            discoveries = result[0]
                            returned_meta = result[1] if len(result) > 1 else {}
                        else:
                            discoveries = result
                            returned_meta = {}
                        items = list(discoveries) if discoveries else []
                        scan_meta.update(returned_meta)
                        scan_meta['discoveries'] = len(items)
                        # Task completed without exception — promote to 'scanned' unless
                        # the handler explicitly set a terminal status (unavailable/access_denied/failed+error)
                        if scan_meta.get('status') not in ('unavailable', 'access_denied') and not scan_meta.get('error'):
                            scan_meta['status'] = 'scanned'
                    else:
                        task.cancel()
                        scan_meta['status'] = 'failed'
                        scan_meta['error'] = 'ScanTimeout'
                        scan_meta['error_message'] = f'Exceeded {service_timeout}s'
                except Exception as e:
                    logger.error(f"[{account_id}] Scan failed {service}/{region}: {e}")
                    scan_meta['status'] = 'failed'
                    scan_meta['error'] = type(e).__name__
                    scan_meta['error_message'] = str(e)[:500]

            count = len(items)
            if items:
                async with results_lock:
                    acct_results[(service, region)] = items

            scan_meta['duration_ms'] = int((time.time() - task_start) * 1000)
            async with meta_lock:
                acct_meta.append(scan_meta)
            timer.record_service(account_id, scan_meta)

            total_discovered += count
            completed_tasks += 1

            if count > 0 or completed_tasks % 100 == 0 or completed_tasks == total_tasks:
                elapsed = time.time() - scan_start
                self.phase_logger.info(
                    f"  [{completed_tasks}/{total_tasks}] [{account_id}] "
                    f"{service}/{region}: {count} items | "
                    f"total={total_discovered} | {elapsed:.0f}s"
                )
            return count

        async def scan_account(acct: Dict[str, str]) -> None:
            """Scan all services for one account — global + regional pools in parallel."""
            account_id = acct['id']
            acct_name = acct.get('name', account_id)

            async with account_sem:
                self.phase_logger.info(
                    f"[ORG] Starting account {account_id} ({acct_name})"
                )
                timer.account_start(account_id)

                # Clone scanner for this account (assume role if org mode)
                if account_id == root_account_id:
                    acct_scanner = self.scanner
                elif hasattr(self.scanner, 'clone_for_account'):
                    acct_scanner = self.scanner.clone_for_account(account_id)
                else:
                    acct_scanner = self.scanner

                acct_results: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
                acct_meta: List[Dict[str, Any]] = []
                results_lock = asyncio.Lock()
                meta_lock = asyncio.Lock()

                # Build per-pool queues
                global_queue: asyncio.Queue = asyncio.Queue()
                regional_queue: asyncio.Queue = asyncio.Queue()

                for svc in global_services:
                    global_queue.put_nowait((svc, primary_region))
                for svc in regional_services:
                    for rgn in scan_regions:
                        regional_queue.put_nowait((svc, rgn))

                g_total = global_queue.qsize()
                r_total = regional_queue.qsize()

                self.phase_logger.info(
                    f"[ORG] [{account_id}] "
                    f"global_queue={g_total}, regional_queue={r_total}"
                )

                # ── Global pool worker ───────────────────────────────────
                async def global_worker() -> None:
                    while True:
                        try:
                            svc, rgn = global_queue.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                        await scan_one(
                            acct_scanner, account_id, svc, rgn,
                            global_sem, acct_results, acct_meta,
                            results_lock, meta_lock,
                        )

                # ── Regional pool worker ─────────────────────────────────
                async def regional_worker() -> None:
                    while True:
                        try:
                            svc, rgn = regional_queue.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                        await scan_one(
                            acct_scanner, account_id, svc, rgn,
                            regional_sem, acct_results, acct_meta,
                            results_lock, meta_lock,
                        )

                # Run global and regional pools CONCURRENTLY within this account.
                # We spawn min(queue_size, sem_limit) workers for each pool so
                # we never create more tasks than there is work.
                g_workers = min(g_total, max_global) if g_total else 0
                r_workers = min(r_total, max_regional) if r_total else 0

                timer.pool_start(account_id, 'global')
                timer.pool_start(account_id, 'regional')

                await asyncio.gather(
                    *[global_worker() for _ in range(g_workers)],
                    *[regional_worker() for _ in range(r_workers)],
                )

                timer.pool_end(account_id, 'global')
                timer.pool_end(account_id, 'regional')

                all_account_results[account_id] = acct_results
                all_account_metadata[account_id] = acct_meta

                timer.account_end(account_id)
                acct_resources = sum(len(v) for v in acct_results.values())
                self.phase_logger.info(
                    f"[ORG] Finished account {account_id}: "
                    f"{acct_resources} resources across {len(acct_results)} service-region pairs"
                )

        # Run all accounts concurrently (bounded by account_sem inside scan_account)
        await asyncio.gather(*[scan_account(acct) for acct in org_accounts])

        scan_executor.shutdown(wait=False)

        timer.phase1_done()
        scan_elapsed = time.time() - scan_start
        self.phase_logger.info(
            f"Phase 1 (scan) complete: {total_discovered} total discoveries "
            f"in {scan_elapsed:.0f}s across {len(org_accounts)} accounts"
        )

        # ── Phase 1b: Persist scan-attempt metadata ─────────────────────────
        if self.use_database and self.db:
            for account_id, acct_meta in all_account_metadata.items():
                failed = [m for m in acct_meta if m['status'] == 'failed']
                denied = [m for m in acct_meta if m['status'] == 'access_denied']
                unavail = [m for m in acct_meta if m['status'] == 'unavailable']
                zero = [m for m in acct_meta if m['status'] == 'scanned' and m['discoveries'] == 0]
                self.phase_logger.info(
                    f"[{account_id}] service summary: {len(acct_meta)} total | "
                    f"{len(failed)} failed | {len(denied)} access_denied | "
                    f"{len(unavail)} unavailable | {len(zero)} scanned/0"
                )
                for m in failed:
                    self.phase_logger.warning(
                        f"  [{account_id}] FAILED: {m['service']}/{m['region']} "
                        f"— {m.get('error', '')} {m.get('error_message', '')}"
                    )
                try:
                    for meta_item in acct_meta:
                        self.db.store_service_scan_result(scan_id, meta_item)
                except Exception as e:
                    logger.warning(f"Failed to persist scan metadata for {account_id} (non-critical): {e}")

        # ── Phase 2: UPLOAD — bulk write per account ─────────────────────────
        timer.phase2_start()
        if self.use_database and self.db:
            uploader = DiscoveryUploader(self.db)
            total_uploaded = 0
            for account_id, acct_results in all_account_results.items():
                if not acct_results:
                    continue
                acct_total = sum(len(v) for v in acct_results.values())
                self.phase_logger.info(
                    f"Phase 2 (upload) [{account_id}]: writing {acct_total} discoveries"
                )
                uploaded = uploader.upload_scan_results(
                    scan_id=scan_id,
                    customer_id=customer_id,
                    tenant_id=tenant_id,
                    provider=provider,
                    account_id=account_id,
                    hierarchy_type=hierarchy_type,
                    results=acct_results,
                )
                total_uploaded += uploaded
                self.phase_logger.info(
                    f"Phase 2 (upload) [{account_id}] complete: {uploaded} rows"
                )
            self.phase_logger.info(
                f"Phase 2 (upload) ALL ACCOUNTS complete: {total_uploaded} total rows"
            )
        timer.phase2_done()

        if self.use_database and self.db:
            self.db.update_scan_status(scan_id, 'completed')

        # ── Timing report — log + persist to DB ─────────────────────────────
        timer.log_summary(
            self.phase_logger.info,
            global_services=global_services,
            regional_services=regional_services,
            scan_regions=scan_regions,
        )
        if self.use_database and self.db:
            try:
                timing_report = timer.report(global_services, regional_services, scan_regions)
                self.db.update_scan_metadata(scan_id, {'timing': timing_report})
            except Exception as e:
                logger.warning(f"Failed to persist timing report (non-critical): {e}")

        elapsed = time.time() - scan_start
        self.phase_logger.info(
            f"Discovery scan completed: {total_discovered} discoveries in {elapsed:.0f}s "
            f"({len(org_accounts)} accounts, {len(services)} services, {len(scan_regions)} regions)"
        )
        return scan_id

    # ── Helpers ──────────────────────────────────────────────────────────────

    async def _enumerate_org_accounts(self, root_account_id: str) -> List[Dict[str, str]]:
        """
        Return accounts to scan.

        If scanner.list_org_accounts() returns data → org mode, scan all accounts.
        Otherwise → single-account mode, return just root_account_id.
        """
        try:
            org_accounts = await self.scanner.list_org_accounts()
        except Exception as e:
            logger.warning(f"list_org_accounts() error: {e} — using single account")
            org_accounts = []

        if org_accounts:
            self.phase_logger.info(
                f"[ORG] Org mode: {len(org_accounts)} accounts found"
            )
            # Ensure the root account is always included (it may not be in the org listing
            # if the caller is a delegated admin rather than the management account).
            ids_found = {a['id'] for a in org_accounts}
            if root_account_id not in ids_found:
                org_accounts.insert(0, {'id': root_account_id, 'name': root_account_id})
            return org_accounts

        # Single-account mode
        return [{'id': root_account_id, 'name': root_account_id}]

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

    def _get_check_services(self, provider: str) -> set:
        """Return set of services that have check rules (need full discovery incl. dependents)."""
        if not self.check_db_reader:
            logger.warning("CheckDBReader unavailable, running full scan for all services")
            return set()
        try:
            return self.check_db_reader.get_check_services(provider=provider)
        except Exception as e:
            logger.warning(f"Failed to load check services: {e} — full scan for all")
            return set()

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
