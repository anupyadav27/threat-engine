import json
import os
import boto3
import yaml
import logging
from typing import Any, List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from aws_compliance_python_engine.utils.inventory_reporter import save_scan_results
from aws_compliance_python_engine.utils.inventory_reporter import save_split_scan_results
from aws_compliance_python_engine.auth.aws_auth import get_boto3_session, get_session_for_account
import threading

# Ensure logs directory exists and set up file logger
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, f"compliance_{os.getenv('HOSTNAME', 'local')}.log")
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger('compliance-boto3')
if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
    fh = logging.FileHandler(log_path)
    fh.setLevel(os.getenv('LOG_LEVEL', 'INFO'))
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    logger.addHandler(fh)

# Retry/backoff settings
MAX_RETRIES = int(os.getenv('COMPLIANCE_MAX_RETRIES', '5'))
BASE_DELAY = float(os.getenv('COMPLIANCE_BASE_DELAY', '0.8'))
BACKOFF_FACTOR = float(os.getenv('COMPLIANCE_BACKOFF_FACTOR', '2.0'))

# Botocore retry/timeout config
BOTO_CONFIG = BotoConfig(
    retries={'max_attempts': int(os.getenv('BOTO_MAX_ATTEMPTS', '5')), 'mode': os.getenv('BOTO_RETRY_MODE', 'standard')},
    read_timeout=int(os.getenv('BOTO_READ_TIMEOUT', '60')),
    connect_timeout=int(os.getenv('BOTO_CONNECT_TIMEOUT', '10')),
    max_pool_connections=int(os.getenv('BOTO_MAX_POOL_CONNECTIONS', '50')),
)

# Toggle caching
ENABLE_CALL_CACHE = os.getenv('COMPLIANCE_ENABLE_CALL_CACHE', 'true').lower() == 'true'

# ------------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------------

def extract_value(obj: Any, path: str):
    parts = path.split('.')
    current = obj
    for idx, part in enumerate(parts):
        if isinstance(current, list):
            result = []
            for item in current:
                sub = extract_value(item, '.'.join(parts[idx:]))
                result.extend(sub if isinstance(sub, list) else [sub])
            return result
        if part.endswith('[]'):
            key = part[:-2]
            arr = current.get(key, []) if isinstance(current, dict) else []
            result = []
            for item in arr:
                sub = extract_value(item, '.'.join(parts[idx+1:]))
                result.extend(sub if isinstance(sub, list) else [sub])
            return result
        else:
            if not isinstance(current, dict):
                return None
            current = current.get(part)
            if current is None:
                return None
    return current

def evaluate_field(value: Any, operator: str, expected: Any = None) -> bool:
    if operator == 'exists':
        exists = value is not None
        if expected is None:
            return exists
        return exists == bool(expected)
    if operator == 'equals':
        return value == expected
    if operator == 'contains':
        if isinstance(value, list):
            return expected in value
        # Compare as strings for non-list scalars to avoid type issues
        return str(expected) in (str(value) if value is not None else '')
    return False

def load_enabled_services_with_scope():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.json")
    with open(config_path) as f:
        data = json.load(f)
    return [(s["name"], s.get("scope", "regional")) for s in data["services"] if s.get("enabled")]

def load_service_rules(service_name):
    rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, f"{service_name}_rules.yaml")
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    return rules[service_name]

def _retry_call(func, *args, **kwargs):
    for attempt in range(MAX_RETRIES):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                raise
            delay = BASE_DELAY * (BACKOFF_FACTOR ** attempt)
            logger.debug(f"Retrying after error: {e} (attempt {attempt+1}/{MAX_RETRIES}, sleep {delay:.2f}s)")
            sleep(delay)

def _client_identity(client) -> Tuple[str, str]:
    try:
        return client.meta.service_model.service_name, client.meta.region_name or 'us-east-1'
    except Exception:
        return 'unknown', 'us-east-1'

def _make_hashable(obj: Any):
    if isinstance(obj, dict):
        return tuple(sorted((k, _make_hashable(v)) for k, v in obj.items()))
    if isinstance(obj, (list, tuple, set)):
        return tuple(_make_hashable(v) for v in obj)
    return obj

def call_boto3(client, action, params):
    method = getattr(client, action)
    return _retry_call(method, **params) if params else _retry_call(method)

def call_boto3_cached(client, action, params, cache: Dict, lock: threading.RLock):
    if not ENABLE_CALL_CACHE:
        return call_boto3(client, action, params)
    service, region = _client_identity(client)
    key = (service, region, action, _make_hashable(params) if params else None)
    with lock:
        if key in cache:
            return cache[key]
    resp = call_boto3(client, action, params)
    with lock:
        cache[key] = resp
    return resp

def discover_accounts(base_session: boto3.session.Session) -> List[str]:
    scan_accounts_env = os.getenv('SCAN_ACCOUNTS')
    if scan_accounts_env:
        return [a.strip() for a in scan_accounts_env.split(',') if a.strip()]
    try:
        org_scan = os.getenv('ORG_SCAN', 'false').lower() == 'true'
        sts = base_session.client('sts', config=BOTO_CONFIG)
        current_acct = sts.get_caller_identity()['Account']
        if not org_scan:
            return [current_acct]
        org = base_session.client('organizations', config=BOTO_CONFIG)
        accounts: List[str] = []
        token: Optional[str] = None
        while True:
            kwargs = {'NextToken': token} if token else {}
            resp = org.list_accounts(**kwargs)
            for acct in resp.get('Accounts', []):
                if acct.get('Status') == 'ACTIVE':
                    accounts.append(acct['Id'])
            token = resp.get('NextToken')
            if not token:
                break
        if current_acct not in accounts:
            accounts.append(current_acct)
        return accounts
    except Exception as e:
        logger.warning(f"Organizations unavailable, defaulting to current account only: {e}")
        try:
            return [base_session.client('sts', config=BOTO_CONFIG).get_caller_identity()['Account']]
        except Exception:
            return ["unknown"]

def get_allowed_regions(session: boto3.session.Session) -> List[str]:
    scan_regions_env = os.getenv('SCAN_REGIONS')
    if scan_regions_env:
        return [r.strip() for r in scan_regions_env.split(',') if r.strip()]
    try:
        ec2 = session.client('ec2', region_name='us-east-1', config=BOTO_CONFIG)
        resp = call_boto3(ec2, 'describe_regions', {'AllRegions': True})
        regions = [r['RegionName'] for r in resp.get('Regions', []) if r.get('OptInStatus') in ('opted-in', 'opt-in-not-required')]
        return regions
    except Exception as e:
        logger.warning(f"DescribeRegions failed, defaulting to session regions list: {e}")
        return session.get_available_regions('ec2')

def _apply_error_policy(call: Dict[str, Any], e: Exception, action: str) -> Optional[bool]:
    code = None
    if isinstance(e, ClientError):
        code = e.response.get('Error', {}).get('Code')
    errors_as_fail = set(call.get('errors_as_fail', []) or [])
    errors_as_pass = set(call.get('errors_as_pass', []) or [])
    errors_as_skip = set(call.get('errors_as_skip', []) or [])
    if code:
        if code in errors_as_fail:
            return False
        if code in errors_as_pass:
            return True
        if code in errors_as_skip:
            return True
    err_str = str(e)
    for c in errors_as_fail:
        if c in err_str:
            return False
    for c in errors_as_pass:
        if c in err_str:
            return True
    for c in errors_as_skip:
        if c in err_str:
            return True
    return None

def run_global_service(service_name, session_override: Optional[boto3.session.Session] = None):
    service_rules = load_service_rules(service_name)
    checks_output = []
    discovery_vars: Dict[str, Dict[str, Any]] = {}
    discovery_results: Dict[str, List[Any]] = {}
    session = session_override or get_boto3_session(default_region='us-east-1')
    client = session.client(service_name, region_name='us-east-1', config=BOTO_CONFIG)
    # per-service cache
    cache: Dict = {}
    cache_lock = threading.RLock()
    try:
        for d in service_rules.get('discovery', []):
            for call in d.get('calls', []):
                action = call['action']
                for_each = d.get('for_each')
                param_name = d.get('param')
                if not for_each:
                    params = {}
                    resp = call_boto3_cached(client, action, params, cache, cache_lock)
                    for field in call.get('fields', []):
                        path = field['path']
                        var = field.get('var')
                        mapping = field.get('map') or {}
                        value = extract_value(resp, path)
                        values = value if isinstance(value, list) else [value]
                        mapped_values = []
                        for v in values:
                            if (v in (None, '')) and ('' in mapping):
                                mapped_values.append(mapping[''])
                            elif v in mapping:
                                mapped_values.append(mapping[v])
                            else:
                                mapped_values.append(v)
                        # store list output for discovery_id
                        discovery_results[d['discovery_id']] = discovery_results.get(d['discovery_id'], []) + [mv for mv in mapped_values if mv is not None]
                else:
                    resources = discovery_results.get(for_each, []) or []
                    resources = [r for r in resources if r]
                    out_values = discovery_results.setdefault(d['discovery_id'], [])
                    for idx, resource in enumerate(resources):
                        params = {param_name: resource} if param_name else {}
                        resp = call_boto3_cached(client, action, params, cache, cache_lock)
                        for field in call.get('fields', []):
                            path = field['path']
                            var = field.get('var')
                            mapping = field.get('map') or {}
                            value = extract_value(resp, path)
                            v = (value[0] if isinstance(value, list) else value)
                            if (v in (None, '')) and ('' in mapping):
                                v = mapping['']
                            elif v in mapping:
                                v = mapping[v]
                            out_values.append(v)
                            if var:
                                # capture per-resource variables
                                discovery_vars.setdefault(str(resource), {})[var] = v
    except Exception as e:
        logger.warning(f"Global discovery failed for {service_name}: {e}")
        return {'inventory': discovery_results, 'checks': [], 'service': service_name, 'scope': 'global', 'unavailable': True}
    for check in service_rules.get('checks', []):
        for_each = check.get('for_each')
        param = check.get('param')
        resources = discovery_results.get(for_each, []) if for_each else [None]
        resources = [r for r in (resources or []) if (r is not None or not for_each)]
        def eval_resource(idx_resource):
            idx, resource = idx_resource
            # pick region from discovered vars when present; default to us-east-1 for global services
            region_for_resource = discovery_vars.get(str(resource), {}).get('region', 'us-east-1')
            client_for_check = session.client(service_name, region_name=region_for_resource or 'us-east-1', config=BOTO_CONFIG)
            call_results = []
            record = {'check_id': check['check_id'], 'region': region_for_resource}
            if param:
                record[param] = resource
            for call in check['calls']:
                action = call['action']
                params = {param: resource} if param else {}
                if param and param.endswith('Ids') and not isinstance(resource, list):
                    params = {param: [resource]}
                try:
                    resp = call_boto3_cached(client_for_check, action, params, cache, cache_lock)
                    call_pass = True
                    for field in call.get('fields', []):
                        path = field['path']
                        operator = field.get('operator')
                        expected = field.get('expected')
                        value = extract_value(resp, path)
                        field_result = all(evaluate_field(v, operator, expected) for v in value) if isinstance(value, list) else evaluate_field(value, operator, expected)
                        call_pass = call_pass and field_result
                    call_results.append(call_pass)
                except Exception as e:
                    policy = _apply_error_policy(call, e, action)
                    if policy is not None:
                        call_results.append(policy)
                    else:
                        record['result'] = 'ERROR'
                        record['error'] = str(e)
                        call_results.append(False)
            multi_step = check.get('multi_step', False)
            logic = check.get('logic', 'AND')
            final = (all(call_results) if (not multi_step or logic == 'AND') else any(call_results)) if call_results else False
            record['result'] = 'PASS' if final else ('FAIL' if 'result' not in record or record['result'] != 'ERROR' else record['result'])
            return record
        with ThreadPoolExecutor(max_workers=int(os.getenv('COMPLIANCE_ENGINE_MAX_WORKERS', '16'))) as ex:
            for rec in ex.map(eval_resource, enumerate(resources)):
                checks_output.append(rec)
    return {'inventory': discovery_results, 'checks': checks_output, 'service': service_name, 'scope': 'global'}

def run_regional_service(service_name, region, session_override: Optional[boto3.session.Session] = None):
    service_rules = load_service_rules(service_name)
    checks_output = []
    discovery_vars: Dict[str, List[Any]] = {}
    discovery_results: Dict[str, List[Any]] = {}
    session = session_override or get_boto3_session(default_region=region)
    client = session.client(service_name, region_name=region, config=BOTO_CONFIG)
    cache: Dict = {}
    cache_lock = threading.RLock()
    try:
        for d in service_rules.get('discovery', []):
            for call in d.get('calls', []):
                action = call['action']
                for_each = d.get('for_each')
                param_name = d.get('param')
                if not for_each:
                    params = {}
                    resp = call_boto3_cached(client, action, params, cache, cache_lock)
                    for field in call.get('fields', []):
                        path = field['path']
                        var = field.get('var')
                        mapping = field.get('map') or {}
                        value = extract_value(resp, path)
                        values = value if isinstance(value, list) else [value]
                        mapped_values = []
                        for v in values:
                            if (v in (None, "")) and ("" in mapping):
                                mapped_values.append(mapping[""])
                            elif v in mapping:
                                mapped_values.append(mapping[v])
                            else:
                                mapped_values.append(v)
                        if var:
                            discovery_vars.setdefault(d['discovery_id'], []).extend(mapped_values)
                        discovery_results[d['discovery_id']] = discovery_vars.get(d['discovery_id'], [])
                else:
                    resources = discovery_results.get(for_each, []) or []
                    resources = [r for r in resources if r]
                    out_values = discovery_results.setdefault(d['discovery_id'], [])
                    for resource in resources:
                        params = {param_name: resource} if param_name else {}
                        resp = call_boto3_cached(client, action, params, cache, cache_lock)
                        for field in call.get('fields', []):
                            path = field['path']
                            mapping = field.get('map') or {}
                            value = extract_value(resp, path)
                            v = (value[0] if isinstance(value, list) else value)
                            if (v in (None, "")) and ("" in mapping):
                                v = mapping[""]
                            elif v in mapping:
                                v = mapping[v]
                            out_values.append(v)
    except Exception as e:
        logger.info(f"Service unavailable or unauthorized: service={service_name} region={region}: {e}")
        return {'inventory': discovery_results, 'checks': [], 'service': service_name, 'scope': 'regional', 'region': region, 'unavailable': True, 'error': str(e)}
    for check in service_rules.get('checks', []):
        for_each = check.get('for_each')
        param = check.get('param')
        resources = discovery_results.get(for_each, []) if for_each else [None]
        resources = [r for r in (resources or []) if (r is not None or not for_each)]
        def eval_resource(resource):
            client_for_check = client
            call_results = []
            record = {'check_id': check['check_id'], 'region': region}
            if param:
                record[param] = resource
            for call in check['calls']:
                action = call['action']
                params = {param: resource} if param else {}
                if param and param.endswith('Ids') and not isinstance(resource, list):
                    params = {param: [resource]}
                try:
                    resp = call_boto3_cached(client_for_check, action, params, cache, cache_lock)
                    call_pass = True
                    for field in call.get('fields', []):
                        path = field['path']
                        operator = field.get('operator')
                        expected = field.get('expected')
                        value = extract_value(resp, path)
                        field_result = all(evaluate_field(v, operator, expected) for v in value) if isinstance(value, list) else evaluate_field(value, operator, expected)
                        call_pass = call_pass and field_result
                    call_results.append(call_pass)
                except Exception as e:
                    policy = _apply_error_policy(call, e, action)
                    if policy is not None:
                        call_results.append(policy)
                    else:
                        record['result'] = 'ERROR'
                        record['error'] = str(e)
                        call_results.append(False)
            multi_step = check.get('multi_step', False)
            logic = check.get('logic', 'AND')
            final = (all(call_results) if (not multi_step or logic == 'AND') else any(call_results)) if call_results else False
            record['result'] = 'PASS' if final else ('FAIL' if 'result' not in record or record['result'] != 'ERROR' else record['result'])
            return record
        with ThreadPoolExecutor(max_workers=int(os.getenv('COMPLIANCE_ENGINE_MAX_WORKERS', '16'))) as ex:
            for rec in ex.map(eval_resource, resources):
                checks_output.append(rec)
    return {'inventory': discovery_results, 'checks': checks_output, 'service': service_name, 'scope': 'regional', 'region': region}

# Uniform alias for regional services




def main():
    services_with_scope = load_enabled_services_with_scope()
    base_session = get_boto3_session()
    outputs: List[Dict[str, Any]] = []
    tasks = []
    with ThreadPoolExecutor(max_workers=int(os.getenv('COMPLIANCE_ENGINE_MAX_WORKERS', '16'))) as ex:
        for account_id in discover_accounts(base_session):
            target_session = get_session_for_account(
                account_id=account_id,
                role_name=os.getenv('ASSUME_ROLE_NAME'),
                default_region='us-east-1',
                base_profile=os.getenv('AWS_PROFILE'),
                external_id=os.getenv('AWS_EXTERNAL_ID'),
            )
            allowed_regions = get_allowed_regions(target_session)
            for service_name, scope in services_with_scope:
                if scope == 'global':
                    tasks.append(ex.submit(run_global_service, service_name, target_session))
                else:
                    for region in allowed_regions:
                        tasks.append(ex.submit(run_regional_service, service_name, region, target_session))
        for fut in as_completed(tasks):
            try:
                outputs.append(fut.result())
            except Exception as e:
                logger.exception('Task failed')
                outputs.append({'error': str(e)})
    try:
        acct_meta = base_session.client('sts', config=BOTO_CONFIG).get_caller_identity()['Account']
    except Exception:
        acct_meta = None
    print(json.dumps(outputs, indent=2))
    output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'output'))
    path = save_scan_results(outputs, output_dir, acct_meta)
    logger.info(f"Saved boto3 engine results to: {path}")
    print(f"Saved boto3 engine results to: {path}")
    # Also write split outputs per service in a timestamped folder
    split_folder = save_split_scan_results(outputs, output_dir, acct_meta)
    logger.info(f"Saved split results under: {split_folder}")
    print(f"Saved split results under: {split_folder}")

if __name__ == "__main__":
    main()
