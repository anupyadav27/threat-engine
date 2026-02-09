"""
Check Engine - Phase 2: Run checks against database or NDJSON files (hybrid approach)
"""
import os
import sys
import yaml
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _project_root() -> Path:
    """Repo root (relative to this file)."""
    # In container, use /app; otherwise calculate from file
    if Path("/app").exists():
        return Path("/app")
    return Path(__file__).resolve().parent.parent.parent.parent


from engine.service_scanner import extract_value, evaluate_condition, resolve_template
from engine.database_manager import DatabaseManager
from engine.discovery_reader import DiscoveryReader
from engine.rule_reader import RuleReader
from utils.phase_logger import PhaseLogger

logger = logging.getLogger(__name__)

class CheckEngine:
    """Engine for running checks against database or NDJSON discoveries (hybrid)"""
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None, use_ndjson: Optional[bool] = None):
        """
        Initialize check engine
        
        Args:
            db_manager: DatabaseManager instance for check results (optional if using NDJSON)
            use_ndjson: If True, use NDJSON files; If False, use database; 
                       If None, auto-detect from environment
        """
        self.db = db_manager  # For storing check results
        self.discovery_reader = DiscoveryReader()  # For reading discoveries from discoveries DB
        self.use_ndjson = self._determine_mode(use_ndjson)
        self.phase_logger = None

        # Initialize RuleReader for loading rules from database
        self.rule_reader = None
        try:
            self.rule_reader = RuleReader()
            if self.rule_reader.check_connection():
                logger.info("RuleReader initialized — will load rules from rule_checks table")
            else:
                logger.warning("RuleReader connection failed, will use YAML rules only")
                self.rule_reader = None
        except Exception as e:
            logger.warning(f"Failed to initialize RuleReader: {e}")
            self.rule_reader = None

        if not self.use_ndjson and not self.db:
            raise ValueError("DatabaseManager required when not using NDJSON mode")

        logger.info(f"CheckEngine initialized: mode={'NDJSON' if self.use_ndjson else 'DATABASE'}, rule_reader={'yes' if self.rule_reader else 'no'}")
    
    def _determine_mode(self, use_ndjson: Optional[bool]) -> bool:
        """Determine whether to use NDJSON or database mode"""
        if use_ndjson is not None:
            return use_ndjson
        
        # Auto-detect from environment
        env_mode = os.getenv('CHECK_MODE', '').lower()
        if env_mode in ('ndjson', 'file', 'local'):
            return True
        elif env_mode in ('database', 'db', 'production'):
            return False
        
        # Default: Use database if connection available, else NDJSON
        if self.db:
            try:
                conn = self.db._get_connection()
                self.db._return_connection(conn)
                return False  # Database available, use it
            except Exception:
                logger.warning("Database connection failed, falling back to NDJSON mode")
                return True

        return False  # Default to database mode
    
    def _load_discoveries_from_ndjson(self, scan_id: str, discovery_id: str, 
                                     service: str, hierarchy_id: str) -> List[Dict]:
        """
        Load discoveries from NDJSON files (local mode)
        
        Args:
            scan_id: Discovery scan ID
            discovery_id: Discovery ID to filter (e.g., 'aws.s3.list_buckets')
            service: Service name (e.g., 's3')
            hierarchy_id: Hierarchy ID (account_id, etc.)
        
        Returns:
            List of discovery items with emitted_fields
        """
        # Use OUTPUT_DIR env var if set (for Kubernetes), otherwise use project root
        output_base = os.getenv("OUTPUT_DIR")
        if output_base:
            # OUTPUT_DIR points to discoveries folder, use it directly
            base_output_dir = Path(output_base).parent
        else:
            base_output_dir = _project_root() / "engine_output" / "engine_configscan_aws" / "output"
        
        # Use new structure: discoveries/
        discoveries_dir = base_output_dir / "discoveries" / scan_id / "discovery"
        
        # Fallback to old structure for backward compatibility
        if not discoveries_dir.exists():
            discoveries_dir = base_output_dir / "discoveries" / scan_id / "discovery"
        
        if not discoveries_dir.exists():
            logger.warning(f"Discoveries directory not found (tried both new and old paths)")
            return []
        
        # Find matching NDJSON files
        # Pattern: {hierarchy_id}_{region}_{service}.ndjson or {hierarchy_id}_global_{service}.ndjson
        pattern = f"{hierarchy_id}_*_{service}.ndjson"
        files = list(discoveries_dir.glob(pattern))
        
        # Also check for global services (no region)
        global_pattern = f"{hierarchy_id}_global_{service}.ndjson"
        global_files = list(discoveries_dir.glob(global_pattern))
        files.extend(global_files)
        
        if not files:
            logger.debug(f"No NDJSON files found matching pattern: {pattern}")
            return []
        
        items = []
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        try:
                            record = json.loads(line.strip())
                            
                            # Filter by discovery_id
                            if record.get('discovery_id') != discovery_id:
                                continue
                            
                            # Filter by hierarchy_id
                            if record.get('hierarchy_id') != hierarchy_id:
                                continue
                            
                            # Extract emitted_fields
                            emitted_fields = record.get('emitted_fields', {})
                            if isinstance(emitted_fields, str):
                                emitted_fields = json.loads(emitted_fields)
                            
                            # Build item record similar to database format
                            item_record = {
                                'resource_arn': record.get('resource_arn'),
                                'resource_id': record.get('resource_id'),
                                'service': record.get('service', service),
                                'region': record.get('region'),
                                'discovery_id': record.get('discovery_id'),
                                'emitted_fields': emitted_fields,
                                'scan_timestamp': record.get('scan_timestamp')
                            }
                            
                            items.append(item_record)
                            
                        except json.JSONDecodeError as e:
                            logger.warning(f"Invalid JSON in {file} line {line_num}: {e}")
                            continue
                        except Exception as e:
                            logger.warning(f"Error parsing line {line_num} in {file}: {e}")
                            continue
            
            except Exception as e:
                logger.error(f"Error reading file {file}: {e}")
                continue
        
        logger.debug(f"Loaded {len(items)} items from NDJSON for discovery_id={discovery_id}")
        return items
    
    def _load_discoveries_from_database(self, discovery_id: str, tenant_id: str,
                                       hierarchy_id: str, scan_id: str, service: str = None) -> List[Dict]:
        """
        Load discoveries from discoveries database (cross-engine integration)
        
        Args:
            discovery_id: Discovery ID to query
            tenant_id: Tenant ID
            hierarchy_id: Hierarchy ID
            scan_id: Scan ID
            service: Optional service name to filter
        
        Returns:
            List of discovery items from discoveries database
        """
        # Use DiscoveryReader to read from discoveries database
        items = self.discovery_reader.read_discovery_records(
            discovery_id=discovery_id,
            tenant_id=tenant_id,
            hierarchy_id=hierarchy_id,
            scan_id=scan_id,
            service=service
        )

        # Return items in the format the check evaluator expects:
        # Each item must have 'emitted_fields' key (dict) plus resource identifiers at top level.
        # DiscoveryReader already returns items with 'emitted_fields' as a dict (parsed JSONB).
        # We just need to ensure resource identifiers are at the top level.
        if items:
            logger.info(f"[DB] Loaded {len(items)} discovery records for {discovery_id}")
        return items
    
    def _load_discoveries(self, discovery_id: str, tenant_id: str, hierarchy_id: str,
                         scan_id: str, service: str) -> List[Dict]:
        """
        Load discoveries from either NDJSON or database based on mode
        
        Returns:
            List of discovery items
        """
        if self.use_ndjson:
            return self._load_discoveries_from_ndjson(
                scan_id=scan_id,
                discovery_id=discovery_id,
                service=service,
                hierarchy_id=hierarchy_id
            )
        else:
            return self._load_discoveries_from_database(
                discovery_id=discovery_id,
                tenant_id=tenant_id,
                hierarchy_id=hierarchy_id,
                scan_id=scan_id,
                service=service
            )
    
    def _extract_resource_identifiers(self, item_record: Dict, emitted_fields: Dict,
                                     hierarchy_id: str = None, 
                                     service: str = None,
                                     discovery_id: str = None,
                                     rule_id: str = None,
                                     region: str = None) -> Dict[str, Any]:
        """
        Extract resource_arn and resource_id using discovery_id as primary source.
        
        Strategy:
        1. Extract service from rule_id (e.g., aws.ec2.account.* → ec2)
        2. Map discovery_id to resource_type (e.g., describe_fpga_images → fpga-image)
        3. Extract resource_id from emitted_fields based on discovery patterns
        4. Generate ARN using service_list.json
        5. Only use account ARN for truly account-level checks
        
        Args:
            item_record: Discovery item record with top-level fields
            emitted_fields: Parsed emitted_fields dictionary
            hierarchy_id: Account ID or hierarchy identifier
            service: Service name (extracted from rule_id if not provided)
            discovery_id: Discovery ID (e.g., aws.ec2.describe_fpga_images)
            rule_id: Rule ID (e.g., aws.ec2.ami.not_publicly_shared_configured)
            region: AWS region
        
        Returns:
            Dict with resource_arn and resource_id
        """
        resource_arn = item_record.get('resource_arn')
        resource_id = item_record.get('resource_id')
        
        # Get service from item_record if not provided
        if not service:
            service = item_record.get('service')
        
        # Get region from item_record if not provided
        if not region:
            region = item_record.get('region', '')
        
        # Get hierarchy_id from item_record if not provided
        if not hierarchy_id:
            hierarchy_id = item_record.get('hierarchy_id') or item_record.get('account_id')
        
        # Step 1: Extract service from rule_id if not provided
        if not service and rule_id:
            parts = rule_id.split('.')
            if len(parts) >= 2 and parts[0] == 'aws':
                service = parts[1]  # aws.ec2.account.* → ec2
        
        # Step 2: Try to extract ARN/ID from emitted_fields (existing recursive search)
        if not resource_arn or not resource_id:
            def find_nested_value(data: Any, patterns: List[str], is_arn: bool = False) -> Any:
                """Recursively search for a value matching patterns"""
                if isinstance(data, dict):
                    for key, value in data.items():
                        # Check if key matches pattern
                        key_lower = key.lower()
                        if any(pattern.lower() in key_lower for pattern in patterns):
                            if isinstance(value, str):
                                if is_arn and value.startswith('arn:aws:'):
                                    return value  # Found ARN
                                elif not is_arn and value and not value.startswith('arn:'):
                                    return value  # Found ID/Name
                        # Recurse into nested dicts
                        if isinstance(value, (dict, list)):
                            result = find_nested_value(value, patterns, is_arn)
                            if result:
                                return result
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, (dict, list)):
                            result = find_nested_value(item, patterns, is_arn)
                            if result:
                                return result
                return None
            
            # Common ARN field patterns (including service-specific)
            arn_patterns = ['Arn', 'ARN', 'arn', 'ResourceArn', 'resource_arn', 'ResourceARN', 
                           'MasterAccountArn', 'AccountArn', 'SubscriptionArn']
            
            # Common ID field patterns
            id_patterns = ['Id', 'ID', 'id', 'ResourceId', 'resource_id', 'ResourceID',
                          'Name', 'name', 'ResourceName', 'MasterAccountId', 'AccountId']
            
            if not resource_arn:
                resource_arn = find_nested_value(emitted_fields, arn_patterns, is_arn=True)
            
            if not resource_id:
                resource_id = find_nested_value(emitted_fields, id_patterns, is_arn=False)
                # If still not found, try extracting from ARN
                if not resource_id and resource_arn:
                    # Extract resource ID from ARN (last part after /)
                    try:
                        if '/' in resource_arn:
                            resource_id = resource_arn.split('/')[-1]
                        elif ':' in resource_arn:
                            parts = resource_arn.split(':')
                            if len(parts) >= 6:
                                resource_id = parts[-1]
                    except:
                        pass
        
        # Step 3: Use discovery_id to determine resource_type and extract ARN/ID
        # GENERIC APPROACH: Use discovery_resource_mapper (no hardcoding)
        if not resource_arn and discovery_id and service and hierarchy_id:
            from utils.discovery_resource_mapper import (
                get_discovery_mapping,
                extract_resource_id_from_emitted,
                extract_resource_arn_from_emitted,
                is_account_level_configuration
            )
            
            # Get resource type, ARN patterns, and ID patterns dynamically from service_list.json
            resource_type, arn_patterns, id_patterns = get_discovery_mapping(discovery_id, emitted_fields)
            
            # Try to extract ARN directly first (most reliable)
            if not resource_arn and arn_patterns:
                resource_arn = extract_resource_arn_from_emitted(emitted_fields, arn_patterns)
                logger.debug(f"[ARN-DIRECT] Tried ARN patterns {arn_patterns[:3]} for {discovery_id}, found: {resource_arn is not None}")
            
            # Extract resource_id using discovery-specific patterns
            if not resource_id and id_patterns:
                resource_id = extract_resource_id_from_emitted(emitted_fields, id_patterns)
                logger.debug(f"[ID-EXTRACT] Tried ID patterns {id_patterns[:3]} for {discovery_id}, found: {resource_id}")
            
            # Generate ARN if we have service, resource_id, and hierarchy_id
            if not resource_arn and service and resource_id and hierarchy_id and resource_type:
                try:
                    from utils.reporting_manager import generate_arn
                    from utils.discovery_resource_mapper import load_service_config
                    
                    # Load service config to check scope
                    service_config = load_service_config(service)
                    service_scope = service_config.get('scope', 'regional') if service_config else 'regional'
                    
                    # For regional services without region, use 'us-east-1' as default
                    arn_region = region
                    if not arn_region or arn_region == 'global' or arn_region == 'None':
                        if service_scope == 'regional':
                            arn_region = 'us-east-1'  # Default region for regional services
                            logger.debug(f"[ARN-GEN] Using default region 'us-east-1' for {service}")
                        else:
                            arn_region = ''  # Global services don't need region
                    
                    # Generate ARN using service_list.json pattern
                    resource_arn = generate_arn(
                        service=service,
                        region=arn_region,
                        account_id=hierarchy_id,
                        resource_id=str(resource_id),
                        resource_type=resource_type
                    )
                    logger.debug(f"[ARN-GEN] Generated ARN from discovery_id: {resource_arn[:80]} for {service}/{resource_id} (type: {resource_type})")
                except Exception as e:
                    logger.debug(f"[ARN-GEN] Failed to generate ARN for {service}/{resource_id} (type: {resource_type}): {e}")
        
        # Step 4: Account ARN for truly account-level configurations
        # GENERIC APPROACH: Use is_account_level_configuration (no hardcoding)
        if not resource_arn and discovery_id and hierarchy_id:
            from utils.discovery_resource_mapper import is_account_level_configuration
            
            if is_account_level_configuration(discovery_id):
                # Generate account-level ARN with service context
                if service:
                    # Infer config_type from discovery operation name (generic approach)
                    operation = discovery_id.split('.')[-1] if '.' in discovery_id else ''
                    
                    # Map operation patterns to config types (generic, pattern-based)
                    if 'account_attributes' in operation:
                        config_type = 'account-attribute'
                    elif 'encryption_settings' in operation or 'encryption' in operation:
                        config_type = 'encryption-settings'
                    elif 'resource_policies' in operation or 'policies' in operation:
                        config_type = 'resource-policy'
                    elif 'block_public_access' in operation or 'public_access' in operation:
                        config_type = 'block-public-access'
                    elif 'allocation_tags' in operation or operation.endswith('_tags'):
                        config_type = 'tag'
                    elif 'event_categories' in operation or 'categories' in operation:
                        config_type = 'event-category'
                    elif 'catalogs' in operation:
                        config_type = 'catalog'
                    elif 'settings' in operation:
                        config_type = 'settings'
                    elif 'endpoints' in operation:
                        config_type = 'endpoint'
                    elif 'status' in operation:
                        config_type = 'status'
                    else:
                        config_type = 'configuration'
                    
                    config_id = resource_id or 'default'
                    
                    resource_arn = f"arn:aws:{service}:{region or ''}:{hierarchy_id}:{config_type}/{config_id}"
                    logger.debug(f"[ARN-ACCOUNT] Generated account-level ARN: {resource_arn} (type: {config_type})")
                else:
                    # Fallback to generic account ARN
                    resource_arn = f"arn:aws:::{hierarchy_id}:account/{hierarchy_id}"
                    resource_id = hierarchy_id
                    logger.debug(f"[ARN-ACCOUNT] Using generic account ARN: {resource_arn}")
        
        return {
            'resource_arn': resource_arn,
            'resource_id': resource_id
        }
    
    def _store_check_result(self, check_scan_id: str, customer_id: str, tenant_id: str,
                            provider: str, hierarchy_id: str, hierarchy_type: str,
                            rule_id: str, item_record: Dict, status: str,
                            checked_fields: List[str], finding_data: Dict):
        """
        Store check result (database or file-based)
        """
        if not self.use_ndjson and self.db:
            # Extract resource_uid (primary) and resource_arn (AWS-specific)
            resource_uid = item_record.get('resource_uid') or item_record.get('resource_arn')
            resource_arn = item_record.get('resource_arn')
            
            # Store in database
            self.db.store_check_result(
                scan_id=check_scan_id,
                customer_id=customer_id,
                tenant_id=tenant_id,
                provider=provider,
                hierarchy_id=hierarchy_id,
                hierarchy_type=hierarchy_type,
                rule_id=rule_id,
                resource_arn=resource_arn,
                resource_uid=resource_uid,
                resource_id=item_record.get('resource_id'),
                resource_type=item_record.get('service'),
                status=status,
                checked_fields=checked_fields,
                finding_data=finding_data
            )
        # If NDJSON mode, results will be written to file in _export_check_results_to_file
    
    def _evaluate_conditions(self, conditions: Dict, context: Dict) -> bool:
        """Evaluate check conditions (same logic as service_scanner)"""
        if 'all' in conditions:
            return all(self._evaluate_conditions(c, context) for c in conditions['all'])
        elif 'any' in conditions:
            return any(self._evaluate_conditions(c, context) for c in conditions['any'])
        else:
            var = conditions.get('var')
            op = conditions.get('op')
            value = conditions.get('value')
            
            if isinstance(value, str) and '{{' in value:
                value = resolve_template(value, context)
            
            actual_value = extract_value(context, var) if var else None
            return evaluate_condition(actual_value, op, value)
    
    def _extract_checked_fields(self, conditions: Dict) -> List[str]:
        """Extract field names from conditions"""
        fields = []
        if 'all' in conditions or 'any' in conditions:
            for sub_cond in conditions.get('all', []) + conditions.get('any', []):
                fields.extend(self._extract_checked_fields(sub_cond))
        else:
            var = conditions.get('var', '')
            if var.startswith('item.'):
                fields.append(var.replace('item.', ''))
        return list(set(fields))  # Remove duplicates
    
    def run_check_scan(self, discovery_scan_id: str, customer_id: str, tenant_id: str,
                      provider: str, hierarchy_id: str, hierarchy_type: str,
                      services: List[str], check_source: str = 'default',
                      use_ndjson: Optional[bool] = None,
                      check_scan_id: str = None,
                      scan_id: str = None) -> Dict[str, Any]:
        """
        Run checks against discoveries (hybrid: NDJSON or database)

        Args:
            discovery_scan_id: Discovery scan ID to check against
            customer_id: Customer ID
            tenant_id: Tenant ID
            provider: CSP provider
            hierarchy_id: Hierarchy ID
            hierarchy_type: Hierarchy type
            services: List of services to check
            check_source: 'default' or 'custom' (loads from different folders)
            use_ndjson: Override mode (None = use instance default)
            check_scan_id: UUID from API server (if None, generates one)
            scan_id: Deprecated alias for discovery_scan_id

        Returns:
            Dict with scan results summary
        """
        # Support legacy 'scan_id' parameter
        if discovery_scan_id is None and scan_id is not None:
            discovery_scan_id = scan_id

        # Override mode if specified
        use_ndjson_mode = use_ndjson if use_ndjson is not None else self.use_ndjson

        # Use API-provided check_scan_id or generate one
        import uuid as _uuid
        if not check_scan_id:
            check_scan_id = str(_uuid.uuid4())

        # Setup phase logger
        output_base = os.getenv("OUTPUT_DIR")
        if output_base:
            base_output_dir = Path(output_base).parent
        else:
            base_output_dir = _project_root() / "engine_output" / "engine_configscan_aws" / "output"
        output_dir = base_output_dir / "checks" / check_scan_id
        self.phase_logger = PhaseLogger(check_scan_id, 'checks', output_dir)

        mode_str = "NDJSON" if use_ndjson_mode else "DATABASE"
        self.phase_logger.info(f"Starting check scan (mode: {mode_str}) against discovery scan: {discovery_scan_id}")
        self.phase_logger.info(f"  Services: {len(services)}, Check source: {check_source}")

        # Create check scan record (only if database available)
        if not use_ndjson_mode and self.db:
            self.db.create_scan(
                scan_id=check_scan_id,
                customer_id=customer_id,
                tenant_id=tenant_id,
                provider=provider,
                hierarchy_id=hierarchy_id,
                hierarchy_type=hierarchy_type,
                scan_type='check',
                metadata={
                    'discovery_scan_id': discovery_scan_id,
                    'services': services,
                    'check_source': check_source,
                    'mode': mode_str
                },
                discovery_scan_id=discovery_scan_id
            )
        
        # Store results in memory for NDJSON mode
        check_results = [] if use_ndjson_mode else None
        
        total_checks = 0
        total_passed = 0
        total_failed = 0
        total_errors = 0
        
        # Process each service
        for service_idx, service in enumerate(services, 1):
            self.phase_logger.info(f"[{service_idx}/{len(services)}] Processing checks for {service}...")
            self.phase_logger.progress(service, None, 'started', {})
            
            try:
                # Load checks from YAML and/or database, merge by rule_id
                checks_by_id = {}

                # 1. Load from YAML file (base checks — lowest priority)
                engine_dir = _project_root() / "engine_check" / "engine_check_aws"
                checks_file = engine_dir / "services" / service / "checks" / check_source / f"{service}.checks.yaml"

                if checks_file.exists():
                    with open(checks_file) as f:
                        checks_config = yaml.safe_load(f)
                    yaml_checks = checks_config.get('checks', [])
                    for c in yaml_checks:
                        rid = c.get('rule_id')
                        if rid:
                            checks_by_id[rid] = c
                    self.phase_logger.info(f"  [{service}] Loaded {len(yaml_checks)} checks from YAML")

                # 2. Load from rule_checks DB table (overrides YAML for same rule_id)
                if self.rule_reader:
                    try:
                        db_checks = self.rule_reader.read_checks_for_service(service, provider)
                        for c in db_checks:
                            rid = c.get('rule_id')
                            if rid:
                                checks_by_id[rid] = c
                        if db_checks:
                            self.phase_logger.info(f"  [{service}] Loaded {len(db_checks)} checks from database (rule_checks)")
                    except Exception as e:
                        self.phase_logger.warning(f"  [{service}] Failed to load DB rules: {e}")

                checks = list(checks_by_id.values())

                if not checks:
                    self.phase_logger.warning(f"  ⚠️  No checks found for {service} (checked YAML and DB)")
                    continue

                self.phase_logger.info(f"  Found {len(checks)} total checks (merged)")

                # Pre-load discovery data: cache by discovery_id to avoid re-querying
                discovery_ids_needed = set()
                for check in checks:
                    fe = check.get('for_each')
                    if fe:
                        discovery_ids_needed.add(fe)

                discovery_cache = {}
                for did in discovery_ids_needed:
                    items = self._load_discoveries(
                        discovery_id=did,
                        tenant_id=tenant_id,
                        hierarchy_id=hierarchy_id,
                        scan_id=discovery_scan_id,
                        service=service
                    )
                    discovery_cache[did] = items

                cached_with_data = sum(1 for v in discovery_cache.values() if v)
                self.phase_logger.info(f"  Pre-loaded {cached_with_data}/{len(discovery_cache)} discovery types with data")

                # Run each check
                for check in checks:
                    rule_id = check.get('rule_id')
                    if not rule_id:
                        continue

                    for_each = check.get('for_each')  # Discovery ID
                    conditions = check.get('conditions')

                    if not for_each or not conditions:
                        self.phase_logger.warning(f"  ⚠️  Check {rule_id} missing for_each or conditions")
                        continue

                    # Use cached discovery data
                    discovery_items = discovery_cache.get(for_each, [])

                    if not discovery_items:
                        self.phase_logger.debug(f"  No discoveries found for {for_each}")
                        continue

                    self.phase_logger.debug(f"  Evaluating {rule_id} against {len(discovery_items)} items")
                    
                    # Evaluate check for each item
                    for item_record in discovery_items:
                        try:
                            # Parse emitted fields
                            emitted_fields = item_record.get('emitted_fields')
                            if isinstance(emitted_fields, str):
                                item_data = json.loads(emitted_fields)
                            elif isinstance(emitted_fields, dict):
                                item_data = emitted_fields
                            else:
                                item_data = {}
                            
                            # WORKAROUND: If emitted_fields has single key matching operation name, unwrap it
                            # This handles cases where dependent discoveries store as: {'get_stage': {actual_data}}
                            if item_data and len(item_data) == 1:
                                single_key = list(item_data.keys())[0]
                                # Check if key looks like an operation name (starts with get_, list_, describe_)
                                if any(single_key.startswith(prefix) for prefix in ['get_', 'list_', 'describe_']):
                                    nested_value = item_data[single_key]
                                    # If nested value is a dict with 'item' key containing data, use that
                                    if isinstance(nested_value, dict):
                                        if 'item' in nested_value:
                                            item_data = nested_value.get('item', {}) or nested_value
                                            logger.debug(f"[UNWRAP] Unwrapped nested operation data from '{single_key}.item'")
                                        else:
                                            item_data = nested_value
                                            logger.debug(f"[UNWRAP] Unwrapped nested operation data from '{single_key}'")
                            
                            # Extract resource identifiers from emitted_fields if missing at top level
                            resource_info = self._extract_resource_identifiers(
                                item_record, 
                                item_data,
                                hierarchy_id=hierarchy_id,
                                service=service,
                                discovery_id=for_each,
                                rule_id=rule_id,
                                region=item_record.get('region')
                            )
                            resource_arn = resource_info.get('resource_arn')
                            resource_id = resource_info.get('resource_id')
                            
                            # Evaluate conditions
                            context = {'item': item_data}
                            result = self._evaluate_conditions(conditions, context)
                            
                            # Extract checked fields
                            checked_fields = self._extract_checked_fields(conditions)
                            
                            # Determine status
                            status = 'PASS' if result else 'FAIL'
                            if status == 'PASS':
                                total_passed += 1
                            else:
                                total_failed += 1
                            
                            # Prepare finding data
                            finding_data = {
                                'rule_id': rule_id,
                                'service': service,
                                'discovery_id': for_each,
                                'resource_arn': resource_arn,
                                'resource_id': resource_id,
                                'status': status,
                                'checked_fields': checked_fields
                            }
                            
                            # Store result (database or memory)
                            if use_ndjson_mode:
                                # Store in memory for later file export
                                check_results.append({
                                    'check_scan_id': check_scan_id,
                                    'discovery_scan_id': discovery_scan_id,
                                    'customer_id': customer_id,
                                    'tenant_id': tenant_id,
                                    'provider': provider,
                                    'hierarchy_id': hierarchy_id,
                                    'hierarchy_type': hierarchy_type,
                                    'rule_id': rule_id,
                                    'resource_arn': resource_arn,
                                    'resource_id': resource_id,
                                    'resource_type': item_record.get('service'),
                                    'status': status,
                                    'checked_fields': checked_fields,
                                    'finding_data': finding_data,
                                    'scan_timestamp': datetime.now().isoformat()
                                })
                            else:
                                # Store in database
                                self._store_check_result(
                                    check_scan_id=check_scan_id,
                                    customer_id=customer_id,
                                    tenant_id=tenant_id,
                                    provider=provider,
                                    hierarchy_id=hierarchy_id,
                                    hierarchy_type=hierarchy_type,
                                    rule_id=rule_id,
                                    item_record=item_record,
                                    status=status,
                                    checked_fields=checked_fields,
                                    finding_data=finding_data
                                )
                            
                            total_checks += 1
                            
                        except Exception as e:
                            self.phase_logger.error(f"  ❌ Error evaluating {rule_id} for item {item_record.get('resource_arn')}: {e}")
                            total_errors += 1
                            
                            # Store error result
                            error_finding = {
                                'rule_id': rule_id,
                                'service': service,
                                'error': str(e)
                            }
                            
                            if use_ndjson_mode:
                                # Try to extract resource identifiers even for errors
                                try:
                                    emitted_fields = item_record.get('emitted_fields', {})
                                    if isinstance(emitted_fields, str):
                                        emitted_fields = json.loads(emitted_fields)
                                    resource_info = self._extract_resource_identifiers(
                                        item_record, 
                                        emitted_fields,
                                        hierarchy_id=hierarchy_id,
                                        service=service,
                                        discovery_id=for_each,
                                        rule_id=rule_id,
                                        region=item_record.get('region')
                                    )
                                    error_resource_arn = resource_info.get('resource_arn')
                                    error_resource_id = resource_info.get('resource_id')
                                except:
                                    error_resource_arn = item_record.get('resource_arn')
                                    error_resource_id = item_record.get('resource_id')
                                
                                check_results.append({
                                    'check_scan_id': check_scan_id,
                                    'discovery_scan_id': discovery_scan_id,
                                    'customer_id': customer_id,
                                    'tenant_id': tenant_id,
                                    'provider': provider,
                                    'hierarchy_id': hierarchy_id,
                                    'hierarchy_type': hierarchy_type,
                                    'rule_id': rule_id,
                                    'resource_arn': error_resource_arn,
                                    'resource_id': error_resource_id,
                                    'status': 'ERROR',
                                    'finding_data': error_finding,
                                    'scan_timestamp': datetime.now().isoformat()
                                })
                            else:
                                if self.db:
                                    self.db.store_check_result(
                                        scan_id=check_scan_id,
                                        customer_id=customer_id,
                                        tenant_id=tenant_id,
                                        provider=provider,
                                        hierarchy_id=hierarchy_id,
                                        hierarchy_type=hierarchy_type,
                                        rule_id=rule_id,
                                        resource_arn=item_record.get('resource_arn'),
                                        resource_id=item_record.get('resource_id'),
                                        status='ERROR',
                                        finding_data=error_finding
                                    )
                
                self.phase_logger.progress(service, None, 'completed', {
                    'checks': len(checks),
                    'passed': total_passed,
                    'failed': total_failed
                })
                self.phase_logger.info(f"  ✅ {service} completed: {len(checks)} checks evaluated")
                
            except Exception as e:
                self.phase_logger.error(f"  ❌ Error processing {service}: {e}", exc_info=True)
                continue
        
        # Update scan status (database mode only)
        if not use_ndjson_mode and self.db:
            self.db.update_scan_status(check_scan_id, 'completed')
        
        # Export check results to local files
        output_path = self._export_check_results_to_file(
            check_scan_id=check_scan_id,
            discovery_scan_id=discovery_scan_id,
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_id=hierarchy_id,
            services=services,
            check_results=check_results if use_ndjson_mode else None,
            output_dir=output_dir
        )
        
        self.phase_logger.info(f"Check scan completed: {check_scan_id}")
        self.phase_logger.info(f"  Mode: {mode_str}")
        self.phase_logger.info(f"  Total checks: {total_checks}")
        self.phase_logger.info(f"  Passed: {total_passed}, Failed: {total_failed}, Errors: {total_errors}")
        self.phase_logger.info(f"  Output saved to: {output_path}")
        
        return {
            'check_scan_id': check_scan_id,
            'discovery_scan_id': discovery_scan_id,
            'mode': mode_str,
            'total_checks': total_checks,
            'passed': total_passed,
            'failed': total_failed,
            'errors': total_errors,
            'output_path': output_path
        }
    
    def _export_check_results_to_file(self, check_scan_id: str, discovery_scan_id: str,
                                      customer_id: str, tenant_id: str,
                                      provider: str, hierarchy_id: str,
                                      services: List[str],
                                      check_results: Optional[List[Dict]] = None,
                                      output_dir: Optional[Path] = None) -> str:
        """
        Export check results to local files
        
        Args:
            check_results: Pre-loaded results (for NDJSON mode), or None to query from DB
        
        Returns:
            Path to output directory
        """
        from datetime import datetime
        from pathlib import Path
        import json
        
        # Create output directory
        if output_dir is None:
            base_output_dir = _project_root() / "engine_output" / "engine_configscan_aws" / "output"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = base_output_dir / "checks" / check_scan_id
        output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Exporting check results to: {output_dir}")
        
        # Get results (from memory or database)
        if check_results is not None:
            # NDJSON mode: use pre-loaded results
            results = check_results
        else:
            # Database mode: query from database
            if not self.db:
                logger.warning("No database and no pre-loaded results, skipping export")
                return str(output_dir)
            results = self.db.export_check_results(check_scan_id)
        
        # Export as NDJSON
        checks_file = output_dir / "checks.ndjson"
        with open(checks_file, 'w') as f:
            for result in results:
                # Parse JSONB fields if needed
                finding_data = result.get('finding_data', {})
                checked_fields = result.get('checked_fields', [])
                
                if isinstance(finding_data, str):
                    try:
                        finding_data = json.loads(finding_data)
                    except:
                        finding_data = {}
                
                if isinstance(checked_fields, str):
                    try:
                        checked_fields = json.loads(checked_fields)
                    except:
                        checked_fields = []
                
                record = {
                    'scan_id': check_scan_id,
                    'discovery_scan_id': discovery_scan_id,
                    'customer_id': result.get('customer_id'),
                    'tenant_id': result.get('tenant_id'),
                    'provider': result.get('provider'),
                    'hierarchy_id': result.get('hierarchy_id'),
                    'hierarchy_type': result.get('hierarchy_type'),
                    'rule_id': result.get('rule_id'),
                    'resource_arn': result.get('resource_arn'),
                    'resource_id': result.get('resource_id'),
                    'resource_type': result.get('resource_type'),
                    'status': result.get('status'),
                    'checked_fields': checked_fields,
                    'finding_data': finding_data,
                    'scan_timestamp': result.get('scan_timestamp')
                }
                
                # Handle datetime objects
                if isinstance(record.get('scan_timestamp'), datetime):
                    record['scan_timestamp'] = record['scan_timestamp'].isoformat()
                
                f.write(json.dumps(record, default=str) + "\n")
        
        # Create summary
        passed = len([r for r in results if r.get('status') == 'PASS'])
        failed = len([r for r in results if r.get('status') == 'FAIL'])
        errors = len([r for r in results if r.get('status') == 'ERROR'])
        
        summary = {
            'check_scan_id': check_scan_id,
            'discovery_scan_id': discovery_scan_id,
            'customer_id': customer_id,
            'tenant_id': tenant_id,
            'provider': provider,
            'hierarchy_id': hierarchy_id,
            'services': services,
            'scan_timestamp': datetime.now().isoformat(),
            'total_checks': len(results),
            'passed': passed,
            'failed': failed,
            'errors': errors,
            'checks_file': str(checks_file),
            'output_directory': str(output_dir)
        }
        
        summary_file = output_dir / "summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        logger.info(f"  Exported {len(results)} check results to {checks_file.name}")
        logger.info(f"  Summary saved to {summary_file.name}")
        
        return str(output_dir)
    
    def run_checks_for_all_services(self, scan_id: str, customer_id: str,
                                    tenant_id: str, provider: str,
                                    hierarchy_id: str, hierarchy_type: str,
                                    check_source: str = 'default',
                                    use_ndjson: Optional[bool] = None) -> Dict[str, Any]:
        """
        Run checks for ALL services
        
        Args:
            scan_id: Discovery scan ID to use
            check_source: 'default' or 'custom'
            use_ndjson: Override mode
        
        Returns:
            Results summary
        """
        # Get all services with checks
        services_dir = Path("services")
        services = [
            d.name for d in services_dir.iterdir()
            if d.is_dir() and not d.name.startswith('.')
            and (d / "checks" / check_source).exists()
        ]
        
        logger.info(f"Found {len(services)} services with checks")
        
        return self.run_check_scan(
            discovery_scan_id=scan_id,
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_id=hierarchy_id,
            hierarchy_type=hierarchy_type,
            services=services,
            check_source=check_source,
            use_ndjson=use_ndjson
        )
