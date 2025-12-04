import json
import os
import logging
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import requests

import yaml
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.managementgroups import ManagementGroupsAPI

from azure_compliance_python_engine.utils.inventory_reporter import save_scan_results, save_split_scan_results
from azure_compliance_python_engine.auth.azure_auth import get_credential_for_tenant

# Ensure logs directory exists and set up file logger
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, f"compliance_{os.getenv('HOSTNAME', 'local')}.log")
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger('compliance-azure')
if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
    fh = logging.FileHandler(log_path)
    fh.setLevel(os.getenv('LOG_LEVEL', 'INFO'))
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    logger.addHandler(fh)

# Toggle caching
ENABLE_CALL_CACHE = os.getenv('COMPLIANCE_ENABLE_CALL_CACHE', 'true').lower() == 'true'

# ------------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------------

def _as_iterable(obj: Any) -> Optional[List[Any]]:
    if obj is None:
        return None
    if isinstance(obj, list):
        return obj
    if isinstance(obj, (str, bytes, dict)):
        return None
    # Azure SDK pagers implement __iter__
    try:
        iterator = iter(obj)
    except TypeError:
        return None
    return list(iterator)


def extract_value(obj: Any, path: str):
    # Special path to return the object itself (or list of items if iterable)
    if path == '__self__':
        as_iter = _as_iterable(obj)
        return as_iter if as_iter is not None else obj

    parts = path.split('.') if path else []
    current = obj
    for idx, part in enumerate(parts):
        # If current is an iterable (ItemPaged, list, etc.), map over items
        iter_items = _as_iterable(current)
        if iter_items is not None:
            result: List[Any] = []
            for item in iter_items:
                sub = extract_value(item, '.'.join(parts[idx:]))
                result.extend(sub if isinstance(sub, list) else [sub])
            return result
        # Handle dictionary key arrays like key[]
        if part.endswith('[]'):
            key = part[:-2]
            arr = getattr(current, key, None) if not isinstance(current, dict) else current.get(key, [])
            arr_iter = _as_iterable(arr)
            if arr_iter is None:
                arr_iter = []
            result = []
            for item in arr_iter:
                sub = extract_value(item, '.'.join(parts[idx+1:]))
                result.extend(sub if isinstance(sub, list) else [sub])
            return result
        else:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                current = getattr(current, part, None)
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
    if operator == 'not_equals':
        return value != expected
    if operator == 'contains':
        if isinstance(value, list):
            return expected in value
        return str(expected) in (str(value) if value is not None else '')
    if operator == 'not_contains':
        if isinstance(value, list):
            return expected not in value
        return str(expected) not in (str(value) if value is not None else '')
    return False


def _apply_mapping(mapping: Dict[Any, Any], value: Any):
    if not mapping:
        return value
    # If key is hashable, allow direct mapping or fallback for empty-string key
    try:
        if value in mapping:
            return mapping[value]
    except TypeError:
        # Unhashable; ignore mapping by key
        pass
    if value in (None, '') and '' in mapping:
        return mapping['']
    return value

# ------------------------------------------------------------------------------------
# Config loaders
# ------------------------------------------------------------------------------------

def load_enabled_services_with_scope():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "service_list.json")
    with open(config_path) as f:
        data = json.load(f)
    return [(s["name"], s.get("scope", "regional")) for s in data["services"] if s.get("enabled")]


def load_service_rules(service_name: str):
    rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, f"{service_name}_rules.yaml")
    with open(rules_path) as f:
        rules = yaml.safe_load(f)
    
    # Handle both flat and nested structures
    # Flat: {version, provider, service, discovery, checks}
    # Nested: {service_name: {version, provider, discovery, checks}}
    if service_name in rules:
        return rules[service_name]  # Nested structure
    else:
        return rules  # Flat structure (AWS-compatible format)


def load_service_scope_from_rules(service_name: str) -> Optional[str]:
    try:
        rules_path = os.path.join(os.path.dirname(__file__), "..", "services", service_name, f"{service_name}_rules.yaml")
        with open(rules_path) as f:
            data = yaml.safe_load(f)
        
        # Handle both flat and nested structures
        if service_name in data:
            svc = data[service_name]  # Nested
        else:
            svc = data  # Flat
        
        scope = svc.get('scope')
        if scope in ('regional', 'global', 'subscription', 'management_group', 'tenant'):
            return scope
    except Exception:
        return None
    return None

# ------------------------------------------------------------------------------------
# Azure clients
# ------------------------------------------------------------------------------------

def get_default_credential():
    # Honors env vars, Managed Identity, Azure CLI, VSCode, etc
    return DefaultAzureCredential(exclude_visual_studio_code_credential=False)


def discover_subscriptions(credential) -> List[str]:
    scan_subs_env = os.getenv('SCAN_SUBSCRIPTIONS')
    if scan_subs_env:
        return [a.strip() for a in scan_subs_env.split(',') if a.strip()]
    subs_client = SubscriptionClient(credential)
    subs = []
    for s in subs_client.subscriptions.list():
        subs.append(s.subscription_id)
    return subs


def discover_regions(credential, subscription_id: str) -> List[str]:
    subs_client = SubscriptionClient(credential)
    try:
        locs = subs_client.subscriptions.list_locations(subscription_id)
        regions = [loc.name for loc in locs if getattr(loc, 'name', None)]
    except Exception:
        regions = []
    scan_regions_env = os.getenv('SCAN_REGIONS')
    if scan_regions_env:
        wanted = [r.strip() for r in scan_regions_env.split(',') if r.strip()]
        regions = [r for r in regions if r in wanted]
    return regions


def discover_resource_groups(credential, subscription_id: str) -> List[str]:
    try:
        rg_client = ResourceManagementClient(credential, subscription_id)
        return [rg.name for rg in rg_client.resource_groups.list()]
    except Exception:
        return []


def discover_management_groups(credential) -> List[str]:
    try:
        mg_client = ManagementGroupsAPI(credential)
        mgs = [mg.name for mg in mg_client.management_groups.list()]
    except Exception:
        mgs = []
    scan_mgs_env = os.getenv('SCAN_MANAGEMENT_GROUPS')
    if scan_mgs_env:
        wanted = [m.strip() for m in scan_mgs_env.split(',') if m.strip()]
        mgs = [m for m in mgs if m in wanted]
    return mgs

# ------------------------------------------------------------------------------------
# Generic call and cache layer
# ------------------------------------------------------------------------------------

class _CallCache:
    def __init__(self):
        self._cache: Dict = {}
        self._lock = threading.RLock()

    def get(self, key):
        with self._lock:
            return self._cache.get(key)

    def set(self, key, value):
        with self._lock:
            self._cache[key] = value


def _make_hashable(obj: Any):
    if isinstance(obj, dict):
        return tuple(sorted((k, _make_hashable(v)) for k, v in obj.items()))
    if isinstance(obj, (list, tuple, set)):
        return tuple(_make_hashable(v) for v in obj)
    return obj


def call_azure(client_obj: Any, action: str, params: Optional[Dict[str, Any]] = None):
    if action in (None, '', 'self'):
        # Direct resource passthrough handled by caller
        return client_obj
    parts = action.split('.')
    target = client_obj
    for p in parts:
        target = getattr(target, p)
    if params:
        return target(**params)
    return target()


def call_azure_cached(client_obj: Any, action: str, params: Optional[Dict[str, Any]], cache: _CallCache):
    if not ENABLE_CALL_CACHE or action in (None, '', 'self'):
        return call_azure(client_obj, action, params)
    try:
        key = (id(client_obj), action, _make_hashable(params) if params else None)
    except TypeError:
        # Params not hashable; skip cache for this call
        return call_azure(client_obj, action, params)
    hit = cache.get(key)
    if hit is not None:
        return hit
    resp = call_azure(client_obj, action, params)
    cache.set(key, resp)
    return resp

# ------------------------------------------------------------------------------------
# Service runners
# ------------------------------------------------------------------------------------

def _build_client_for_service(service_name: str, subscription_id: str, credential):
    # Lazy import to avoid heavy deps on startup
    # Generated for all 59 Azure services
    if service_name == 'aad':
        return None  # Graph API service, uses different auth
    if service_name == 'aks':
        from azure.mgmt.containerservice import ContainerServiceClient
        return ContainerServiceClient(credential, subscription_id)
    if service_name == 'api':
        from azure.mgmt.apimanagement import ApiManagementClient
        return ApiManagementClient(credential, subscription_id)
    if service_name == 'automation':
        from azure.mgmt.automation import AutomationClient
        return AutomationClient(credential, subscription_id)
    if service_name == 'backup':
        from azure.mgmt.recoveryservices import RecoveryServicesClient
        return RecoveryServicesClient(credential, subscription_id)
    if service_name == 'batch':
        from azure.mgmt.batch import BatchManagementClient
        return BatchManagementClient(credential, subscription_id)
    if service_name == 'billing':
        from azure.mgmt.billing import BillingManagementClient
        return BillingManagementClient(credential, subscription_id)
    if service_name == 'blob':
        from azure.storage.blob import BlobServiceClient
        return BlobServiceClient(credential, subscription_id)
    if service_name == 'cdn':
        from azure.mgmt.cdn import CdnManagementClient
        return CdnManagementClient(credential, subscription_id)
    if service_name == 'certificates':
        from azure.keyvault.certificates import CertificateClient
        return CertificateClient(credential, subscription_id)
    if service_name == 'compute':
        from azure.mgmt.compute import ComputeManagementClient
        return ComputeManagementClient(credential, subscription_id)
    if service_name == 'config':
        from azure.mgmt.appconfiguration import AppConfigurationManagementClient
        return AppConfigurationManagementClient(credential, subscription_id)
    if service_name == 'container':
        from azure.mgmt.containerinstance import ContainerInstanceManagementClient
        return ContainerInstanceManagementClient(credential, subscription_id)
    if service_name == 'containerregistry':
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient
        return ContainerRegistryManagementClient(credential, subscription_id)
    if service_name == 'cosmosdb':
        from azure.mgmt.cosmosdb import CosmosDBManagementClient
        return CosmosDBManagementClient(credential, subscription_id)
    if service_name == 'cost':
        from azure.mgmt.costmanagement import CostManagementClient
        return CostManagementClient(credential, subscription_id)
    if service_name == 'data':
        from azure.mgmt.datafactory import DataFactoryManagementClient
        return DataFactoryManagementClient(credential, subscription_id)
    if service_name == 'databricks':
        from azure.mgmt.databricks import AzureDatabricksManagementClient
        return AzureDatabricksManagementClient(credential, subscription_id)
    if service_name == 'dataprotection':
        from azure.mgmt.dataprotection import DataProtectionClient
        return DataProtectionClient(credential, subscription_id)
    if service_name == 'devops':
        return None  # DevOps uses different API
    if service_name == 'dns':
        from azure.mgmt.dns import DnsManagementClient
        return DnsManagementClient(credential, subscription_id)
    if service_name == 'elastic':
        from azure.mgmt.elastic import ElasticClient
        return ElasticClient(credential, subscription_id)
    if service_name == 'event':
        from azure.mgmt.eventgrid import EventGridManagementClient
        return EventGridManagementClient(credential, subscription_id)
    if service_name == 'files':
        from azure.storage.fileshare import ShareServiceClient
        return ShareServiceClient(credential, subscription_id)
    if service_name == 'front':
        from azure.mgmt.frontdoor import FrontDoorManagementClient
        return FrontDoorManagementClient(credential, subscription_id)
    if service_name == 'function':
        from azure.mgmt.web import WebSiteManagementClient
        return WebSiteManagementClient(credential, subscription_id)
    if service_name == 'hdinsight':
        from azure.mgmt.hdinsight import HDInsightManagementClient
        return HDInsightManagementClient(credential, subscription_id)
    if service_name == 'iam':
        from azure.mgmt.authorization import AuthorizationManagementClient
        return AuthorizationManagementClient(credential, subscription_id)
    if service_name == 'intune':
        return None  # Intune uses Graph API
    if service_name == 'iot':
        from azure.mgmt.iothub import IotHubClient
        return IotHubClient(credential, subscription_id)
    if service_name == 'key':
        from azure.keyvault.keys import KeyClient
        return KeyClient(credential, subscription_id)
    if service_name == 'keyvault':
        from azure.mgmt.keyvault import KeyVaultManagementClient
        return KeyVaultManagementClient(credential, subscription_id)
    if service_name == 'log':
        from azure.mgmt.loganalytics import LogAnalyticsManagementClient
        return LogAnalyticsManagementClient(credential, subscription_id)
    if service_name == 'logic':
        from azure.mgmt.logic import LogicManagementClient
        return LogicManagementClient(credential, subscription_id)
    if service_name == 'machine':
        from azure.mgmt.machinelearningservices import MachineLearningServiceClient
        return MachineLearningServiceClient(credential, subscription_id)
    if service_name == 'management':
        from azure.mgmt.managementgroups import ManagementGroupsAPI
        return ManagementGroupsAPI(credential)
    if service_name == 'managementgroup':
        from azure.mgmt.managementgroups import ManagementGroupsAPI
        return ManagementGroupsAPI(credential)
    if service_name == 'mariadb':
        from azure.mgmt.rdbms.mariadb import MariaDBManagementClient
        return MariaDBManagementClient(credential, subscription_id)
    if service_name == 'monitor':
        from azure.mgmt.monitor import MonitorManagementClient
        return MonitorManagementClient(credential, subscription_id)
    if service_name == 'mysql':
        from azure.mgmt.rdbms.mysql import MySQLManagementClient
        return MySQLManagementClient(credential, subscription_id)
    if service_name == 'netappfiles':
        from azure.mgmt.netapp import NetAppManagementClient
        return NetAppManagementClient(credential, subscription_id)
    if service_name == 'network':
        from azure.mgmt.network import NetworkManagementClient
        return NetworkManagementClient(credential, subscription_id)
    if service_name == 'notification':
        from azure.mgmt.notificationhubs import NotificationHubsManagementClient
        return NotificationHubsManagementClient(credential, subscription_id)
    if service_name == 'policy':
        from azure.mgmt.resource import PolicyClient
        return PolicyClient(credential, subscription_id)
    if service_name == 'postgresql':
        from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient
        return PostgreSQLManagementClient(credential, subscription_id)
    if service_name == 'power':
        from azure.mgmt.powerbidedicated import PowerBIDedicated
        return PowerBIDedicated(credential, subscription_id)
    if service_name == 'purview':
        from azure.mgmt.purview import PurviewManagementClient
        return PurviewManagementClient(credential, subscription_id)
    if service_name == 'rbac':
        from azure.mgmt.authorization import AuthorizationManagementClient
        return AuthorizationManagementClient(credential, subscription_id)
    if service_name == 'redis':
        from azure.mgmt.redis import RedisManagementClient
        return RedisManagementClient(credential, subscription_id)
    if service_name == 'resource':
        from azure.mgmt.resource import ResourceManagementClient
        return ResourceManagementClient(credential, subscription_id)
    if service_name == 'search':
        from azure.mgmt.search import SearchManagementClient
        return SearchManagementClient(credential, subscription_id)
    if service_name == 'security':
        from azure.mgmt.security import SecurityCenter
        return SecurityCenter(credential, subscription_id)
    if service_name == 'sql':
        from azure.mgmt.sql import SqlManagementClient
        return SqlManagementClient(credential, subscription_id)
    if service_name == 'storage':
        from azure.mgmt.storage import StorageManagementClient
        return StorageManagementClient(credential, subscription_id)
    if service_name == 'subscription':
        from azure.mgmt.subscription import SubscriptionClient
        return SubscriptionClient(credential)
    if service_name == 'synapse':
        from azure.mgmt.synapse import SynapseManagementClient
        return SynapseManagementClient(credential, subscription_id)
    if service_name == 'traffic':
        from azure.mgmt.trafficmanager import TrafficManagerManagementClient
        return TrafficManagerManagementClient(credential, subscription_id)
    if service_name == 'webapp':
        from azure.mgmt.web import WebSiteManagementClient
        return WebSiteManagementClient(credential, subscription_id)
    raise ValueError(f"Unsupported service: {service_name}")


def _service_requires_rg(service_rules: Dict[str, Any]) -> bool:
    if service_rules.get('iterate_resource_groups'):
        return True
    for section in ('discovery', 'checks'):
        for item in service_rules.get(section, []) or []:
            if item.get('resource_group_param'):
                return True
            for call in item.get('calls', []) or []:
                if call.get('resource_group_param'):
                    return True
    return False


def _substitute_templates(params: Dict[str, Any], resource: Any) -> Dict[str, Any]:
    """Replace {{field}} templates in params with values from resource object"""
    import re
    
    substituted = {}
    for key, value in params.items():
        if isinstance(value, str) and '{{' in value:
            # Extract template variables like {{name}}, {{resource_group}}
            template_pattern = r'\{\{(\w+)\}\}'
            matches = re.findall(template_pattern, value)
            
            result = value
            for field_name in matches:
                # Try to get value from resource
                field_value = None
                
                if isinstance(resource, dict):
                    field_value = resource.get(field_name)
                elif hasattr(resource, field_name):
                    field_value = getattr(resource, field_name)
                elif field_name == 'resource_group' and hasattr(resource, 'id'):
                    # Extract resource group from Azure resource ID
                    # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
                    resource_id = getattr(resource, 'id', '')
                    if isinstance(resource_id, str) and '/resourceGroups/' in resource_id:
                        parts = resource_id.split('/resourceGroups/')
                        if len(parts) > 1:
                            field_value = parts[1].split('/')[0]
                
                if field_value is not None:
                    result = result.replace('{{' + field_name + '}}', str(field_value))
            
            substituted[key] = result
        else:
            substituted[key] = value
    
    return substituted


def _inject_scoped_params(params: Dict[str, Any], action: Optional[str], region_param: Optional[str], region: Optional[str], rg_param: Optional[str], resource_group: Optional[str], mg_param: Optional[str] = None, management_group: Optional[str] = None):
    if action in (None, 'self'):
        return
    if region_param and region:
        params[region_param] = region
    if rg_param and resource_group:
        params[rg_param] = resource_group
    if mg_param and management_group:
        params[mg_param] = management_group


def run_subscription_service(service_name: str, tenant_id: Optional[str], subscription_id: str, credential):
    service_rules = load_service_rules(service_name)
    checks_output: List[Dict[str, Any]] = []
    discovery_results: Dict[str, List[Any]] = {}
    client = _build_client_for_service(service_name, subscription_id, credential)
    cache = _CallCache()

    use_rg = _service_requires_rg(service_rules)
    resource_groups = discover_resource_groups(credential, subscription_id) if use_rg else [None]

    # Discovery
    try:
        for d in service_rules.get('discovery', []):
            for call in d.get('calls', []):
                action = call.get('action')
                for_each = d.get('for_each')
                param_name = d.get('param')
                region_param = call.get('region_param') or d.get('region_param')
                rg_param = call.get('resource_group_param') or d.get('resource_group_param')
                mg_param = call.get('management_group_param') or d.get('management_group_param')
                if not for_each:
                    for rg in resource_groups:
                        params: Dict[str, Any] = {}
                        _inject_scoped_params(params, action, region_param, None, rg_param, rg, mg_param, None)
                        resp = call_azure_cached(client, action, params, cache) if action not in (None, 'self') else client
                        for field in call.get('fields', []):
                            path = field.get('path', '__self__')
                            mapping = field.get('map') or {}
                            value = extract_value(resp, path)
                            values = value if isinstance(value, list) else [value]
                            for v in values:
                                v_out = _apply_mapping(mapping, v)
                                discovery_results.setdefault(d['discovery_id'], []).append(v_out)
                else:
                    resources = discovery_results.get(for_each, []) or []
                    resources = [r for r in resources if r]
                    out_values = discovery_results.setdefault(d['discovery_id'], [])
                    for rg in resource_groups:
                        for resource in resources:
                            target = resource if action in (None, 'self') else client
                            params: Dict[str, Any] = {}
                            if param_name and action not in (None, 'self'):
                                params[param_name] = resource
                            _inject_scoped_params(params, action, region_param, None, rg_param, rg, mg_param, None)
                            resp = call_azure_cached(target, action, params, cache)
                            for field in call.get('fields', []):
                                path = field.get('path', '__self__')
                                mapping = field.get('map') or {}
                                value = extract_value(resp, path)
                                v = (value[0] if isinstance(value, list) else value)
                                if (v in (None, '')) and ('' in mapping):
                                    v = mapping['']
                                elif v in mapping:
                                    v = mapping[v]
                                out_values.append(_apply_mapping(mapping, v))
    except Exception as e:
        return {'inventory': discovery_results, 'checks': [], 'service': service_name, 'scope': 'subscription', 'tenant': tenant_id, 'subscription': subscription_id, 'unavailable': True, 'error': str(e)}

    # Checks
    for check in service_rules.get('checks', []):
        for_each = check.get('for_each')
        param = check.get('param')
        resources = discovery_results.get(for_each, []) if for_each else [None]
        resources = [r for r in (resources or []) if (r is not None or not for_each)]

        def eval_resource(resource):
            record = {'check_id': check['check_id'], 'tenant': tenant_id, 'subscription': subscription_id}
            if param:
                record[param] = resource
            call_results: List[bool] = []
            for call in check['calls']:
                action = call.get('action')
                region_param = call.get('region_param') or check.get('region_param')
                rg_param = call.get('resource_group_param') or check.get('resource_group_param')
                mg_param = call.get('management_group_param') or check.get('management_group_param')
                target = resource if action in (None, 'self') else client
                params: Dict[str, Any] = call.get('params', {}).copy()  # Get params from call definition
                if param and action not in (None, 'self'):
                    params[param] = resource
                # Substitute templates like {{name}}, {{resource_group}} with actual values
                if resource is not None:
                    params = _substitute_templates(params, resource)
                # iterate each RG if applicable
                rgs = resource_groups if (rg_param and action not in (None, 'self')) else [None]
                for rg in rgs:
                    _inject_scoped_params(params, action, region_param, None, rg_param, rg, mg_param, None)
                    try:
                        resp = call_azure_cached(target, action, params, cache)
                        call_pass = True
                        for field in call.get('fields', []):
                            path = field.get('path', '__self__')
                            operator = field.get('operator')
                            expected = field.get('expected')
                            value = extract_value(resp, path)
                            field_result = all(evaluate_field(v, operator, expected) for v in value) if isinstance(value, list) else evaluate_field(value, operator, expected)
                            call_pass = call_pass and field_result
                        call_results.append(call_pass)
                        if rg:
                            record['resource_group'] = rg
                    except Exception as e:
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

    return {'inventory': discovery_results, 'checks': checks_output, 'service': service_name, 'scope': 'subscription', 'tenant': tenant_id, 'subscription': subscription_id}


def run_global_service(service_name: str, tenant_id: Optional[str], subscription_id: str, credential):
    res = run_subscription_service(service_name, tenant_id, subscription_id, credential)
    res['scope'] = 'global'
    return res


def run_regional_service(service_name: str, tenant_id: Optional[str], subscription_id: str, region: str, credential):
    service_rules = load_service_rules(service_name)
    checks_output: List[Dict[str, Any]] = []
    discovery_results: Dict[str, List[Any]] = {}
    client = _build_client_for_service(service_name, subscription_id, credential)
    cache = _CallCache()

    use_rg = _service_requires_rg(service_rules)
    resource_groups = discover_resource_groups(credential, subscription_id) if use_rg else [None]

    try:
        for d in service_rules.get('discovery', []):
            for call in d.get('calls', []):
                action = call.get('action')
                for_each = d.get('for_each')
                param_name = d.get('param')
                region_param = call.get('region_param') or d.get('region_param')
                rg_param = call.get('resource_group_param') or d.get('resource_group_param')
                mg_param = call.get('management_group_param') or d.get('management_group_param')
                if not for_each:
                    for rg in resource_groups:
                        params: Dict[str, Any] = {}
                        _inject_scoped_params(params, action, region_param, region, rg_param, rg, mg_param, None)
                        resp = call_azure_cached(client, action, params, cache) if action not in (None, 'self') else client
                        for field in call.get('fields', []):
                            path = field.get('path', '__self__')
                            mapping = field.get('map') or {}
                            value = extract_value(resp, path)
                            values = value if isinstance(value, list) else [value]
                            for v in values:
                                v_out = _apply_mapping(mapping, v)
                                discovery_results.setdefault(d['discovery_id'], []).append(v_out)
                else:
                    resources = discovery_results.get(for_each, []) or []
                    resources = [r for r in resources if r]
                    out_values = discovery_results.setdefault(d['discovery_id'], [])
                    for rg in resource_groups:
                        for resource in resources:
                            target = resource if action in (None, 'self') else client
                            params: Dict[str, Any] = {}
                            if param_name and action not in (None, 'self'):
                                params[param_name] = resource
                            _inject_scoped_params(params, action, region_param, region, rg_param, rg, mg_param, None)
                            resp = call_azure_cached(target, action, params, cache)
                            for field in call.get('fields', []):
                                path = field.get('path', '__self__')
                                mapping = field.get('map') or {}
                                value = extract_value(resp, path)
                                v = (value[0] if isinstance(value, list) else value)
                                if (v in (None, '')) and ('' in mapping):
                                    v = mapping['']
                                elif v in mapping:
                                    v = mapping[v]
                                out_values.append(_apply_mapping(mapping, v))
    except Exception as e:
        return {'inventory': discovery_results, 'checks': [], 'service': service_name, 'scope': 'regional', 'tenant': tenant_id, 'subscription': subscription_id, 'region': region, 'unavailable': True, 'error': str(e)}

    for check in service_rules.get('checks', []):
        for_each = check.get('for_each')
        param = check.get('param')
        resources = discovery_results.get(for_each, []) if for_each else [None]
        resources = [r for r in (resources or []) if (r is not None or not for_each)]

        def eval_resource(resource):
            record = {'check_id': check['check_id'], 'tenant': tenant_id, 'subscription': subscription_id, 'region': region}
            if param:
                record[param] = resource
            call_results: List[bool] = []
            for call in check['calls']:
                action = call.get('action')
                region_param = call.get('region_param') or check.get('region_param')
                rg_param = call.get('resource_group_param') or check.get('resource_group_param')
                mg_param = call.get('management_group_param') or check.get('management_group_param')
                target = resource if action in (None, 'self') else client
                params: Dict[str, Any] = {}
                if param and action not in (None, 'self'):
                    params[param] = resource
                rgs = resource_groups if (rg_param and action not in (None, 'self')) else [None]
                for rg in rgs:
                    _inject_scoped_params(params, action, region_param, region, rg_param, rg, mg_param, None)
                    try:
                        resp = call_azure_cached(target, action, params, cache)
                        call_pass = True
                        for field in call.get('fields', []):
                            path = field.get('path', '__self__')
                            operator = field.get('operator')
                            expected = field.get('expected')
                            value = extract_value(resp, path)
                            field_result = all(evaluate_field(v, operator, expected) for v in value) if isinstance(value, list) else evaluate_field(value, operator, expected)
                            call_pass = call_pass and field_result
                        call_results.append(call_pass)
                        if rg:
                            record['resource_group'] = rg
                    except Exception as e:
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

    return {'inventory': discovery_results, 'checks': checks_output, 'service': service_name, 'scope': 'regional', 'tenant': tenant_id, 'subscription': subscription_id, 'region': region}


def _build_client_for_service_mg(service_name: str, credential):
    if service_name == 'policy':
        from azure.mgmt.resource import PolicyClient
        return PolicyClient(credential)
    raise ValueError(f"Unsupported management-group service: {service_name}")


def run_management_group_service(service_name: str, tenant_id: Optional[str], management_group_id: str, credential):
    service_rules = load_service_rules(service_name)
    checks_output: List[Dict[str, Any]] = []
    discovery_results: Dict[str, List[Any]] = {}
    client = _build_client_for_service_mg(service_name, credential)
    cache = _CallCache()

    try:
        for d in service_rules.get('discovery', []):
            for call in d.get('calls', []):
                action = call.get('action')
                for_each = d.get('for_each')
                param_name = d.get('param')
                mg_param = call.get('management_group_param') or d.get('management_group_param')
                if not for_each:
                    params: Dict[str, Any] = {}
                    _inject_scoped_params(params, action, None, None, None, None, mg_param, management_group_id)
                    resp = call_azure_cached(client, action, params, cache) if action not in (None, 'self') else client
                    for field in call.get('fields', []):
                        path = field.get('path', '__self__')
                        mapping = field.get('map') or {}
                        value = extract_value(resp, path)
                        values = value if isinstance(value, list) else [value]
                        for v in values:
                            v_out = _apply_mapping(mapping, v)
                            discovery_results.setdefault(d['discovery_id'], []).append(v_out)
                else:
                    resources = discovery_results.get(for_each, []) or []
                    resources = [r for r in resources if r]
                    out_values = discovery_results.setdefault(d['discovery_id'], [])
                    for resource in resources:
                        target = resource if action in (None, 'self') else client
                        params: Dict[str, Any] = {}
                        if param_name and action not in (None, 'self'):
                            params[param_name] = resource
                        _inject_scoped_params(params, action, None, None, None, None, mg_param, management_group_id)
                        resp = call_azure_cached(target, action, params, cache)
                        for field in call.get('fields', []):
                            path = field.get('path', '__self__')
                            mapping = field.get('map') or {}
                            value = extract_value(resp, path)
                            v = (value[0] if isinstance(value, list) else value)
                            out_values.append(_apply_mapping(mapping, v))
    except Exception as e:
        return {'inventory': discovery_results, 'checks': [], 'service': service_name, 'scope': 'management_group', 'tenant': tenant_id, 'management_group': management_group_id, 'unavailable': True, 'error': str(e)}

    for check in service_rules.get('checks', []):
        for_each = check.get('for_each')
        param = check.get('param')
        resources = discovery_results.get(for_each, []) if for_each else [None]
        resources = [r for r in (resources or []) if (r is not None or not for_each)]

        def eval_resource(resource):
            record = {'check_id': check['check_id'], 'tenant': tenant_id, 'management_group': management_group_id}
            if param:
                record[param] = resource
            call_results: List[bool] = []
            for call in check['calls']:
                action = call.get('action')
                mg_param = call.get('management_group_param') or check.get('management_group_param')
                target = resource if action in (None, 'self') else client
                params: Dict[str, Any] = {}
                if param and action not in (None, 'self'):
                    params[param] = resource
                _inject_scoped_params(params, action, None, None, None, None, mg_param, management_group_id)
                try:
                    resp = call_azure_cached(target, action, params, cache)
                    call_pass = True
                    for field in call.get('fields', []):
                        path = field.get('path', '__self__')
                        operator = field.get('operator')
                        expected = field.get('expected')
                        value = extract_value(resp, path)
                        field_result = all(evaluate_field(v, operator, expected) for v in value) if isinstance(value, list) else evaluate_field(value, operator, expected)
                        call_pass = call_pass and field_result
                    call_results.append(call_pass)
                except Exception as e:
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

    return {'inventory': discovery_results, 'checks': checks_output, 'service': service_name, 'scope': 'management_group', 'tenant': tenant_id, 'management_group': management_group_id}

# ------------------------------------------------------------------------------------
# Tenant (Microsoft Graph) runner
# ------------------------------------------------------------------------------------

def _graph_call(credential: DefaultAzureCredential, method: str, path: str, params: Optional[Dict[str, Any]] = None):
    token = credential.get_token('https://graph.microsoft.com/.default').token
    url = f'https://graph.microsoft.com{path}'
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
    resp = requests.request(method, url, headers=headers, params=params)
    resp.raise_for_status()
    return resp.json()


def run_tenant_service(service_name: str, tenant_id: Optional[str], credential: DefaultAzureCredential):
    service_rules = load_service_rules(service_name)
    checks_output: List[Dict[str, Any]] = []
    discovery_results: Dict[str, List[Any]] = {}
    try:
        for d in service_rules.get('discovery', []):
            for call in d.get('calls', []):
                method = call.get('method', 'GET')
                path = call.get('path')  # e.g., '/v1.0/applications'
                for_each = d.get('for_each')
                param_name = d.get('param')
                if not for_each:
                    data = _graph_call(credential, method, path)
                    for field in call.get('fields', []):
                        v = extract_value(data, field.get('path', '__self__'))
                        values = v if isinstance(v, list) else [v]
                        for item in values:
                            discovery_results.setdefault(d['discovery_id'], []).append(item)
                else:
                    resources = discovery_results.get(for_each, []) or []
                    out_values = discovery_results.setdefault(d['discovery_id'], [])
                    for resource in resources:
                        # Simple param injection by replacing '{param}' in path if present
                        eff_path = path
                        if param_name and isinstance(resource, str):
                            eff_path = path.replace('{'+param_name+'}', resource)
                        data = _graph_call(credential, method, eff_path)
                        for field in call.get('fields', []):
                            v = extract_value(data, field.get('path', '__self__'))
                            out_values.append(v[0] if isinstance(v, list) else v)
    except Exception as e:
        return {'inventory': discovery_results, 'checks': [], 'service': service_name, 'scope': 'tenant', 'tenant': tenant_id, 'unavailable': True, 'error': str(e)}

    for check in service_rules.get('checks', []):
        for_each = check.get('for_each')
        param = check.get('param')
        resources = discovery_results.get(for_each, []) if for_each else [None]
        resources = [r for r in (resources or []) if (r is not None or not for_each)]

        def eval_resource(resource):
            record = {'check_id': check['check_id'], 'tenant': tenant_id}
            if param:
                record[param] = resource
            call_results: List[bool] = []
            for call in check['calls']:
                method = call.get('method', 'GET')
                path = call.get('path')
                eff_path = path
                if param and isinstance(resource, str):
                    eff_path = path.replace('{'+param+'}', resource)
                try:
                    data = _graph_call(credential, method, eff_path)
                    call_pass = True
                    for field in call.get('fields', []):
                        val = extract_value(data, field.get('path', '__self__'))
                        operator = field.get('operator')
                        expected = field.get('expected')
                        field_result = all(evaluate_field(v, operator, expected) for v in val) if isinstance(val, list) else evaluate_field(val, operator, expected)
                        call_pass = call_pass and field_result
                    call_results.append(call_pass)
                except Exception as e:
                    record['result'] = 'ERROR'
                    record['error'] = str(e)
                    call_results.append(False)
            final = all(call_results) if call_results else False
            record['result'] = 'PASS' if final else ('FAIL' if 'result' not in record or record['result'] != 'ERROR' else record['result'])
            return record

        with ThreadPoolExecutor(max_workers=int(os.getenv('COMPLIANCE_ENGINE_MAX_WORKERS', '16'))) as ex:
            for rec in ex.map(eval_resource, resources):
                checks_output.append(rec)

    return {'inventory': discovery_results, 'checks': checks_output, 'service': service_name, 'scope': 'tenant', 'tenant': tenant_id}

# ------------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------------

def main():
    services_with_scope = load_enabled_services_with_scope()

    # Tenants: default current tenant, or list via SCAN_TENANTS
    tenants_env = os.getenv('SCAN_TENANTS')
    tenant_ids = [t.strip() for t in tenants_env.split(',')] if tenants_env else [None]

    outputs: List[Dict[str, Any]] = []
    tasks = []

    with ThreadPoolExecutor(max_workers=int(os.getenv('COMPLIANCE_ENGINE_MAX_WORKERS', '16'))) as ex:
        for tenant_id in tenant_ids:
            credential = get_credential_for_tenant(tenant_id) if tenant_id else get_default_credential()
            for sub_id in discover_subscriptions(credential):
                regions_cache: Optional[List[str]] = None
                for service_name, scope in services_with_scope:
                    yaml_scope = load_service_scope_from_rules(service_name)
                    eff_scope = yaml_scope or scope or 'subscription'
                    if eff_scope == 'regional':
                        if regions_cache is None:
                            regions_cache = discover_regions(credential, sub_id)
                        for region in regions_cache:
                            tasks.append(ex.submit(run_regional_service, service_name, tenant_id, sub_id, region, credential))
                    elif eff_scope == 'global':
                        tasks.append(ex.submit(run_global_service, service_name, tenant_id, sub_id, credential))
                    elif eff_scope == 'management_group':
                        for mg in discover_management_groups(credential):
                            tasks.append(ex.submit(run_management_group_service, service_name, tenant_id, mg, credential))
                    elif eff_scope == 'tenant':
                        tasks.append(ex.submit(run_tenant_service, service_name, tenant_id, credential))
                    else:
                        tasks.append(ex.submit(run_subscription_service, service_name, tenant_id, sub_id, credential))
        for fut in as_completed(tasks):
            try:
                outputs.append(fut.result())
            except Exception as e:
                logger.exception('Task failed')
                outputs.append({'error': str(e)})

    print(json.dumps(outputs, indent=2, default=str))
    output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'output'))
    os.makedirs(output_dir, exist_ok=True)
    acct_meta = None
    path = save_scan_results(outputs, output_dir, acct_meta)
    logger.info(f"Saved azure engine results to: {path}")
    print(f"Saved azure engine results to: {path}")

    split_folder = save_split_scan_results(outputs, output_dir, acct_meta)
    logger.info(f"Saved split results under: {split_folder}")
    print(f"Saved split results under: {split_folder}")

if __name__ == "__main__":
    main() 