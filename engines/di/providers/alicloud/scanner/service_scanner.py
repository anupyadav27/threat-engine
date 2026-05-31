"""
AliCloud Discovery Scanner

Implements AliCloud-specific discovery using handler registry pattern.
Each service handler is a simple function registered via @alicloud_handler decorator.

AliCloud SDK uses the Tea OpenAPI framework — every service has its own
client package (e.g. alibabacloud_ecs20140526, alibabacloud_oss20190517).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple
import asyncio
import logging

from common.models.provider_interface import AuthenticationError, DiscoveryError, DiscoveryScanner

# DCAT-02-AL: catalog-driven emit rendering (DB-backed)
try:
    from common.jinja_renderer import render_emit_item
    _RENDERER_AVAILABLE = True
except ImportError:  # pragma: no cover
    render_emit_item = None  # type: ignore
    _RENDERER_AVAILABLE = False

logger = logging.getLogger(__name__)

_emit_failure_sink: List[Dict[str, Any]] = []
_ALICLOUD_EMIT_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}
_ALICLOUD_SERVICE_LOADED: set = set()


def _load_alicloud_service_emits(service: str) -> None:
    """Populate _ALICLOUD_EMIT_CACHE from rule_discoveries (provider='alicloud')."""
    if service in _ALICLOUD_SERVICE_LOADED:
        return
    _ALICLOUD_SERVICE_LOADED.add(service)
    try:
        from providers.aws.aws_utils.rules import load_service_rules
        rules = load_service_rules(service, provider="alicloud")
    except Exception as exc:
        logger.warning("AliCloud rules load failed for service=%s: %s", service, exc)
        return
    default_template: Optional[Dict[str, Any]] = None
    for disc in (rules or {}).get('discovery', []) or []:
        did = disc.get('discovery_id')
        emit = disc.get('emit') or {}
        item_tmpl = emit.get('item') if isinstance(emit, dict) else None
        valid = isinstance(item_tmpl, dict) and bool(item_tmpl)
        if did:
            _ALICLOUD_EMIT_CACHE[did] = item_tmpl if valid else None
        if valid and default_template is None:
            default_template = item_tmpl
    if default_template is not None:
        _ALICLOUD_EMIT_CACHE[f"_service_default::{service}"] = default_template


def _get_alicloud_emit_template(discovery_id: str) -> Optional[Dict[str, Any]]:
    """Return cached emit.item template, with service-default fallback."""
    if discovery_id in _ALICLOUD_EMIT_CACHE:
        return _ALICLOUD_EMIT_CACHE[discovery_id]
    parts = discovery_id.split('.', 2)
    if len(parts) < 2 or parts[0] != 'alicloud':
        _ALICLOUD_EMIT_CACHE[discovery_id] = None
        return None
    service = parts[1]
    _load_alicloud_service_emits(service)
    direct = _ALICLOUD_EMIT_CACHE.get(discovery_id)
    if direct is not None:
        return direct
    fallback = _ALICLOUD_EMIT_CACHE.get(f"_service_default::{service}")
    _ALICLOUD_EMIT_CACHE[discovery_id] = fallback
    return fallback

# Thread pool for blocking AliCloud SDK calls
_ALICLOUD_EXECUTOR = ThreadPoolExecutor(max_workers=10)

DEFAULT_ALICLOUD_REGIONS = [
    'cn-hangzhou', 'cn-shanghai', 'cn-beijing', 'cn-shenzhen',
    'cn-hongkong', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3',
    'ap-northeast-1', 'eu-central-1', 'us-east-1', 'us-west-1',
]

# ─── Service Handler Registry ──────────────────────────────────────────────────

ALICLOUD_SERVICE_HANDLERS: Dict[str, Callable] = {}


def alicloud_handler(service_name: str):
    """Decorator to register an AliCloud service discovery handler."""
    def decorator(fn: Callable):
        ALICLOUD_SERVICE_HANDLERS[service_name] = fn
        return fn
    return decorator


# ─── Resource Identifier Helper ───────────────────────────────────────────────

def _enrich_alicloud_item(item: Dict, account_id: str, region: str) -> Dict:
    """Inject standard resource identifier fields used by database_manager.

    AliCloud resources use a mix of ARN-style IDs and plain IDs. This maps
    them to resource_arn/resource_uid/resource_id so the DB layer stores them.
    """
    resource_id = (
        item.get('InstanceId')
        or item.get('BucketName')
        or item.get('DBInstanceId')
        or item.get('VSwitchId')
        or item.get('VpcId')
        or item.get('GroupId')
        or item.get('RoleId')
        or item.get('UserId')
        or item.get('PolicyId')
        or item.get('KeyId')
        or item.get('LoadBalancerId')
        or item.get('ClusterId')
        or item.get('TrailId')
        or item.get('id', '')
    )
    if not resource_id:
        discovery_id = item.get('_discovery_id', 'unknown')
        item_keys = [k for k in item.keys() if not k.startswith('_')][:10]
        logger.error("ALICLOUD_RESOURCE_ID_MISSING: discovery_id=%r item keys=%s",
                     discovery_id, item_keys)
        return None
    resource_type = item.get('resource_type', 'alicloud/Resource')
    # AliCloud ARN format: acs:<service>:<region>:<account-id>:<resource>
    service_part = resource_type.split('/')[0].lower().replace('alicloud.', '')
    arn = f"acs:{service_part}:{region}:{account_id}:{resource_id}"

    item['resource_arn'] = arn
    item['resource_id'] = resource_id
    item['resource_uid'] = arn

    item['_raw_response'] = {k: v for k, v in item.items()
                             if not k.startswith('_') and k not in (
                                 'resource_arn', 'resource_uid', 'resource_id', 'resource_type')}

    # DCAT-02-AL: catalog-driven emit rendering
    if _RENDERER_AVAILABLE:
        discovery_id = item.get('_discovery_id')
        if discovery_id:
            template = _get_alicloud_emit_template(discovery_id)
            if template:
                ctx = {
                    'item': item,
                    'response': item,
                    'context': {
                        'account_id': account_id,
                        'region': region,
                        'service': discovery_id.split('.')[1] if '.' in discovery_id else '',
                    },
                }
                try:
                    rendered = render_emit_item(
                        template, ctx,
                        discovery_id=discovery_id,
                        resource_uid=arn,
                        failure_sink=_emit_failure_sink,
                    )
                    if isinstance(rendered, dict) and rendered:
                        item['emitted_fields'] = rendered
                except Exception as exc:  # pragma: no cover
                    logger.warning("AliCloud emit render failed %s: %s", discovery_id, exc)
    return item


# ─── Service Handlers ─────────────────────────────────────────────────────────

@alicloud_handler('ecs')
def _scan_ecs(access_key_id: str, access_key_secret: str, account_id: str,
              region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud ECS instances."""
    try:
        from alibabacloud_ecs20140526.client import Client
        from alibabacloud_ecs20140526 import models as ecs_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region,
        )
        client = Client(cfg)
        resources = []
        page_num = 1
        page_size = 100
        while True:
            req = ecs_models.DescribeInstancesRequest(
                region_id=region, page_number=page_num, page_size=page_size
            )
            resp = client.describe_instances(req)
            instances = resp.body.instances.instance or []
            for inst in instances:
                item = {
                    'InstanceId': inst.instance_id,
                    'InstanceName': inst.instance_name,
                    'Status': inst.status,
                    'RegionId': inst.region_id,
                    'ZoneId': inst.zone_id,
                    'InstanceType': inst.instance_type,
                    'OSType': inst.o_s_type,
                    'ImageId': inst.image_id,
                    'CreationTime': inst.creation_time,
                    'Tags': [{'Key': t.key, 'Value': t.value}
                             for t in (inst.tags.tag or [])] if inst.tags else [],
                    'resource_type': 'alicloud.ecs/Instance',
                    '_discovery_id': 'alicloud.ecs.describe_instances',
                }
                if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
            total = resp.body.total_count or 0
            if page_num * page_size >= total:
                break
            page_num += 1
    except Exception as e:
        logger.warning("AliCloud ECS scan failed [%s]: %s", region, e)
        resources = []
    logger.info("  ecs/%s: %d instances found", region, len(resources))
    return resources


@alicloud_handler('oss')
def _scan_oss(access_key_id: str, access_key_secret: str, account_id: str,
              region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud OSS buckets (region-independent, scanned once from primary region)."""
    try:
        import oss2

        auth = oss2.Auth(access_key_id, access_key_secret)
        service = oss2.Service(auth, f'https://oss-{region}.aliyuncs.com')
        resources = []
        for bucket_info in oss2.BucketIterator(service):
            item = {
                'BucketName': bucket_info.name,
                'Location': getattr(bucket_info, 'location', region),
                'CreationDate': str(getattr(bucket_info, 'creation_date', '')),
                'StorageClass': getattr(bucket_info, 'storage_class', ''),
                'resource_type': 'alicloud.oss/Bucket',
                '_discovery_id': 'alicloud.oss.list_buckets',
            }
            if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
    except Exception as e:
        logger.warning("AliCloud OSS scan failed [%s]: %s", region, e)
        resources = []
    logger.info("  oss/%s: %d buckets found", region, len(resources))
    return resources


@alicloud_handler('rds')
def _scan_rds(access_key_id: str, access_key_secret: str, account_id: str,
              region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud RDS instances."""
    try:
        from alibabacloud_rds20140815.client import Client
        from alibabacloud_rds20140815 import models as rds_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region,
        )
        client = Client(cfg)
        resources = []
        page_num = 1
        page_size = 100
        while True:
            req = rds_models.DescribeDBInstancesRequest(
                region_id=region, page_number=page_num, page_size=page_size
            )
            resp = client.describe_dbinstances(req)
            items = resp.body.items.d_b_instance or []
            for db in items:
                item = {
                    'DBInstanceId': db.d_b_instance_id,
                    'DBInstanceDescription': db.d_b_instance_description,
                    'DBInstanceStatus': db.d_b_instance_status,
                    'Engine': db.engine,
                    'EngineVersion': db.engine_version,
                    'DBInstanceClass': db.d_b_instance_class,
                    'RegionId': db.region_id,
                    'ZoneId': db.zone_id,
                    'CreationTime': db.creation_time,
                    'resource_type': 'alicloud.rds/DBInstance',
                    '_discovery_id': 'alicloud.rds.describe_db_instances',
                }
                if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
            total = resp.body.total_record_count or 0
            if page_num * page_size >= total:
                break
            page_num += 1
    except Exception as e:
        logger.warning("AliCloud RDS scan failed [%s]: %s", region, e)
        resources = []
    logger.info("  rds/%s: %d instances found", region, len(resources))
    return resources


@alicloud_handler('vpc')
def _scan_vpc(access_key_id: str, access_key_secret: str, account_id: str,
              region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud VPCs."""
    try:
        from alibabacloud_vpc20160428.client import Client
        from alibabacloud_vpc20160428 import models as vpc_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region,
        )
        client = Client(cfg)
        resources = []
        page_num = 1
        page_size = 50
        while True:
            req = vpc_models.DescribeVpcsRequest(
                region_id=region, page_number=page_num, page_size=page_size
            )
            resp = client.describe_vpcs(req)
            vpcs = resp.body.vpcs.vpc or []
            for vpc in vpcs:
                item = {
                    'VpcId': vpc.vpc_id,
                    'VpcName': vpc.vpc_name,
                    'Status': vpc.status,
                    'RegionId': vpc.region_id,
                    'CidrBlock': vpc.cidr_block,
                    'IsDefault': vpc.is_default,
                    'CreationTime': vpc.creation_time,
                    'resource_type': 'alicloud.vpc/Vpc',
                    '_discovery_id': 'alicloud.vpc.describe_vpcs',
                }
                if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
            total = resp.body.total_count or 0
            if page_num * page_size >= total:
                break
            page_num += 1
    except Exception as e:
        logger.warning("AliCloud VPC scan failed [%s]: %s", region, e)
        resources = []
    logger.info("  vpc/%s: %d VPCs found", region, len(resources))
    return resources


@alicloud_handler('vpc_route_table')
def _scan_vpc_route_tables(access_key_id: str, access_key_secret: str, account_id: str,
                            region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud VPC route tables (emits alicloud.vpc.describe_route_tables).

    Used by the network engine L2 reachability analysis.
    """
    try:
        from alibabacloud_vpc20160428.client import Client
        from alibabacloud_vpc20160428 import models as vpc_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region,
        )
        client = Client(cfg)
        resources = []
        page_num = 1
        page_size = 50
        while True:
            req = vpc_models.DescribeRouteTableListRequest(
                region_id=region,
                page_number=page_num,
                page_size=page_size,
            )
            resp = client.describe_route_table_list(req)
            tables = resp.body.router_table_list.router_table_list_type or []
            for rt in tables:
                item = {
                    'RouteTableId': rt.route_table_id,
                    'RouteTableName': getattr(rt, 'route_table_name', None),
                    'RouteTableType': getattr(rt, 'route_table_type', None),
                    'VpcId': getattr(rt, 'vpc_id', None),
                    'RegionId': region,
                    'RouteCounts': getattr(rt, 'route_counts', 0),
                    'resource_type': 'alicloud.vpc/RouteTable',
                    '_discovery_id': 'alicloud.vpc.describe_route_tables',
                }
                if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
            total = getattr(resp.body, 'total_count', 0) or 0
            if page_num * page_size >= total:
                break
            page_num += 1
    except Exception as e:
        logger.warning("AliCloud VPC RouteTable scan failed [%s]: %s", region, e)
        resources = []
    logger.info("  vpc_route_table/%s: %d route tables found", region, len(resources))
    return resources


@alicloud_handler('ram')
def _scan_ram(access_key_id: str, access_key_secret: str, account_id: str,
              region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud RAM users (global — scanned once from primary region)."""
    try:
        from alibabacloud_ram20150501.client import Client
        from alibabacloud_ram20150501 import models as ram_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
        )
        client = Client(cfg)
        resources = []

        # Users
        marker = None
        while True:
            req = ram_models.ListUsersRequest()
            if marker:
                req.marker = marker
            resp = client.list_users(req)
            for user in (resp.body.users.user or []):
                item = {
                    'UserId': user.user_id,
                    'UserName': user.user_name,
                    'DisplayName': user.display_name,
                    'Email': getattr(user, 'email', None),
                    'CreateDate': user.create_date,
                    'UpdateDate': user.update_date,
                    'resource_type': 'alicloud.ram/User',
                    '_discovery_id': 'alicloud.ram.list_users',
                }
                if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
            if not resp.body.is_truncated:
                break
            marker = resp.body.marker

        # Roles
        marker = None
        while True:
            req = ram_models.ListRolesRequest()
            if marker:
                req.marker = marker
            resp = client.list_roles(req)
            for role in (resp.body.roles.role or []):
                item = {
                    'RoleId': role.role_id,
                    'RoleName': role.role_name,
                    'Arn': role.arn,
                    'Description': getattr(role, 'description', None),
                    'CreateDate': role.create_date,
                    'UpdateDate': role.update_date,
                    'resource_type': 'alicloud.ram/Role',
                    '_discovery_id': 'alicloud.ram.list_roles',
                }
                if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
            if not resp.body.is_truncated:
                break
            marker = resp.body.marker

    except Exception as e:
        logger.warning("AliCloud RAM scan failed: %s", e)
        resources = []
    logger.info("  ram/%s: %d resources found", region, len(resources))
    return resources


@alicloud_handler('slb')
def _scan_slb(access_key_id: str, access_key_secret: str, account_id: str,
              region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud SLB (Server Load Balancer) instances."""
    try:
        from alibabacloud_slb20140515.client import Client
        from alibabacloud_slb20140515 import models as slb_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region,
        )
        client = Client(cfg)
        resources = []
        page_num = 1
        page_size = 100
        while True:
            req = slb_models.DescribeLoadBalancersRequest(
                region_id=region, page_number=page_num, page_size=page_size
            )
            resp = client.describe_load_balancers(req)
            lbs = resp.body.load_balancers.load_balancer or []
            for lb in lbs:
                item = {
                    'LoadBalancerId': lb.load_balancer_id,
                    'LoadBalancerName': lb.load_balancer_name,
                    'LoadBalancerStatus': lb.load_balancer_status,
                    'RegionId': lb.region_id,
                    'Address': lb.address,
                    'AddressType': lb.address_type,
                    'InternetChargeType': getattr(lb, 'internet_charge_type', None),
                    'CreateTime': lb.create_time,
                    'resource_type': 'alicloud.slb/LoadBalancer',
                    '_discovery_id': 'alicloud.slb.describe_load_balancers',
                }
                if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
            total = resp.body.total_count or 0
            if page_num * page_size >= total:
                break
            page_num += 1
    except Exception as e:
        logger.warning("AliCloud SLB scan failed [%s]: %s", region, e)
        resources = []
    logger.info("  slb/%s: %d load balancers found", region, len(resources))
    return resources


@alicloud_handler('kms')
def _scan_kms(access_key_id: str, access_key_secret: str, account_id: str,
              region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud KMS keys."""
    try:
        from alibabacloud_kms20160120.client import Client
        from alibabacloud_kms20160120 import models as kms_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region,
        )
        client = Client(cfg)
        resources = []
        page_num = 1
        page_size = 100
        while True:
            req = kms_models.ListKeysRequest(
                page_number=page_num, page_size=page_size
            )
            resp = client.list_keys(req)
            keys = resp.body.keys.key or []
            for key in keys:
                item = {
                    'KeyId': key.key_id,
                    'KeyArn': getattr(key, 'key_arn', None),
                    'resource_type': 'alicloud.kms/Key',
                    '_discovery_id': 'alicloud.kms.list_keys',
                }
                if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
            total = resp.body.total_count or 0
            if page_num * page_size >= total:
                break
            page_num += 1
    except Exception as e:
        logger.warning("AliCloud KMS scan failed [%s]: %s", region, e)
        resources = []
    logger.info("  kms/%s: %d keys found", region, len(resources))
    return resources


@alicloud_handler('actiontrail')
def _scan_actiontrail(access_key_id: str, access_key_secret: str, account_id: str,
                      region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud ActionTrail trails."""
    try:
        from alibabacloud_actiontrail20200706.client import Client
        from alibabacloud_actiontrail20200706 import models as at_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region,
        )
        client = Client(cfg)
        resources = []
        req = at_models.DescribeTrailsRequest(include_shadow_trails=False)
        resp = client.describe_trails(req)
        for trail in (resp.body.trail_list or []):
            item = {
                'TrailId': getattr(trail, 'trail_arn', trail.name),
                'Name': trail.name,
                'OssBucketName': getattr(trail, 'oss_bucket_name', None),
                'OssKeyPrefix': getattr(trail, 'oss_key_prefix', None),
                'SlsProjectArn': getattr(trail, 'sls_project_arn', None),
                'Status': getattr(trail, 'status', None),
                'HomeRegion': getattr(trail, 'home_region', region),
                'IsOrganizationTrail': getattr(trail, 'is_organization_trail', False),
                'resource_type': 'alicloud.actiontrail/Trail',
                '_discovery_id': 'alicloud.actiontrail.describe_trails',
            }
            if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
    except Exception as e:
        logger.warning("AliCloud ActionTrail scan failed [%s]: %s", region, e)
        resources = []
    logger.info("  actiontrail/%s: %d trails found", region, len(resources))
    return resources


@alicloud_handler('ack')
def _scan_ack(access_key_id: str, access_key_secret: str, account_id: str,
              region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud ACK (Container Service for Kubernetes) clusters."""
    try:
        from alibabacloud_cs20151215.client import Client
        from alibabacloud_cs20151215 import models as cs_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region,
        )
        client = Client(cfg)
        resources = []
        resp = client.describe_clusters_v1(cs_models.DescribeClustersV1Request(region_id=region))
        for cluster in (resp.body.clusters or []):
            item = {
                'ClusterId': cluster.cluster_id,
                'Name': cluster.name,
                'ClusterType': cluster.cluster_type,
                'State': cluster.state,
                'RegionId': cluster.region_id,
                'Size': cluster.size,
                'KubernetesVersion': getattr(cluster, 'current_version', None),
                'Created': str(cluster.created),
                'resource_type': 'alicloud.cs/Cluster',
                '_discovery_id': 'alicloud.ack.describe_clusters',
            }
            if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
    except Exception as e:
        logger.warning("AliCloud ACK scan failed [%s]: %s", region, e)
        resources = []
    logger.info("  ack/%s: %d clusters found", region, len(resources))
    return resources


@alicloud_handler('security_center')
def _scan_security_center(access_key_id: str, access_key_secret: str, account_id: str,
                           region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud Security Center configuration."""
    try:
        from alibabacloud_sas20181203.client import Client
        from alibabacloud_sas20181203 import models as sas_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region,
        )
        client = Client(cfg)
        resources = []
        req = sas_models.GetAssetSelectionConfigRequest()
        resp = client.get_asset_selection_config(req)
        item = {
            'id': f"security-center-{account_id}",
            'SelectionKey': getattr(resp.body, 'selection_key', None),
            'resource_type': 'alicloud.sas/Config',
            '_discovery_id': 'alicloud.security_center.get_config',
        }
        if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)
    except Exception as e:
        logger.warning("AliCloud SecurityCenter scan failed [%s]: %s", region, e)
        resources = []
    logger.info("  security_center/%s: %d resources found", region, len(resources))
    return resources


@alicloud_handler('ecs_security_groups')
def _scan_ecs_security_groups(access_key_id: str, access_key_secret: str, account_id: str,
                               region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud ECS Security Groups with their ingress/egress rules.

    Emits field names matching check rule expectations:
      - ``Permissions.Permission[].SourceCidrIp`` for source CIDR checks
      - ``Permissions.Permission[].IpProtocol`` for protocol checks
      - ``Permissions.Permission[].PortRange`` for port checks
      - ``Permissions.Permission[].Policy`` for Accept/Drop checks
    """
    try:
        from alibabacloud_ecs20140526.client import Client
        from alibabacloud_ecs20140526 import models as ecs_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region,
        )
        client = Client(cfg)
        resources = []

        # Step 1: list all security groups in the region
        page_num = 1
        page_size = 100
        groups = []
        while True:
            req = ecs_models.DescribeSecurityGroupsRequest(
                region_id=region, page_number=page_num, page_size=page_size
            )
            resp = client.describe_security_groups(req)
            batch = resp.body.security_groups.security_group or []
            groups.extend(batch)
            total = resp.body.total_count or 0
            if page_num * page_size >= total:
                break
            page_num += 1

        # Step 2: for each group, fetch its permission rules
        for grp in groups:
            permissions = []
            try:
                attr_req = ecs_models.DescribeSecurityGroupAttributeRequest(
                    security_group_id=grp.security_group_id,
                    region_id=region,
                )
                attr_resp = client.describe_security_group_attribute(attr_req)
                perms = attr_resp.body.permissions
                if perms and perms.permission:
                    for p in perms.permission:
                        permissions.append({
                            'IpProtocol': getattr(p, 'ip_protocol', None),
                            'PortRange': getattr(p, 'port_range', None),
                            'SourceCidrIp': getattr(p, 'source_cidr_ip', None),
                            'DestCidrIp': getattr(p, 'dest_cidr_ip', None),
                            'Policy': getattr(p, 'policy', None),
                            'Direction': getattr(p, 'direction', None),
                            'Priority': getattr(p, 'priority', None),
                            'NicType': getattr(p, 'nic_type', None),
                        })
            except Exception as perm_err:
                logger.debug("Failed to get permissions for SG %s: %s",
                             grp.security_group_id, perm_err)

            item = {
                'GroupId': grp.security_group_id,
                'SecurityGroupId': grp.security_group_id,
                'SecurityGroupName': getattr(grp, 'security_group_name', None),
                'SecurityGroupType': getattr(grp, 'security_group_type', None),
                'Description': getattr(grp, 'description', None),
                'VpcId': getattr(grp, 'vpc_id', None),
                'RegionId': region,
                'Permissions': {'Permission': permissions},
                'resource_type': 'alicloud.ecs/SecurityGroup',
                '_discovery_id': 'alicloud.ecs.describe_security_groups',
            }
            if (r := _enrich_alicloud_item(item, account_id, region)) is not None: resources.append(r)

    except Exception as e:
        logger.warning("AliCloud ECS SecurityGroups scan failed [%s]: %s", region, e)
        resources = []
    logger.info("  ecs_security_groups/%s: %d groups found", region, len(resources))
    return resources


@alicloud_handler('alb')
def _scan_alb(access_key_id: str, access_key_secret: str, account_id: str,
              region: str, config: Dict) -> List[Dict]:
    """Discover AliCloud Application Load Balancer (ALB) resources.

    Emits resources with discovery_id 'alicloud.alb.DescribeZones' which matches
    the for_each value used in ALB check rules.
    """
    from alibabacloud_tea_openapi import models as open_api_models
    from alibabacloud_tea_util import models as util_models

    resources = []
    try:
        import importlib
        alb_module = importlib.import_module('alibabacloud_alb20200616.client')
        AlbClient = alb_module.Client

        alb_config = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            region_id=region,
            endpoint=f'alb.{region}.aliyuncs.com',
        )
        client = AlbClient(alb_config)
        runtime = util_models.RuntimeOptions()

        # List load balancers
        list_lb_module = importlib.import_module('alibabacloud_alb20200616.models')
        list_req = list_lb_module.ListLoadBalancersRequest()
        list_req.max_results = 100
        try:
            resp = client.list_load_balancers_with_options(list_req, runtime)
            for lb in (resp.body.load_balancers or []):
                lb_id = getattr(lb, 'load_balancer_id', '') or ''
                lb_name = getattr(lb, 'load_balancer_name', '') or ''
                lb_status = getattr(lb, 'load_balancer_status', '') or ''

                item = {
                    'id': lb_id,
                    'LoadBalancerId': lb_id,
                    'LoadBalancerName': lb_name,
                    'LoadBalancerStatus': lb_status,
                    'AddressType': getattr(lb, 'address_type', '') or '',
                    'VpcId': getattr(lb, 'vpc_id', '') or '',
                    'DeletionProtectionEnabled': getattr(lb, 'deletion_protection_config', None) and
                                                 getattr(lb.deletion_protection_config, 'enabled', False),
                    'region': region,
                    'account_id': account_id,
                    'resource_type': 'alicloud.alb/LoadBalancer',
                    '_discovery_id': 'alicloud.alb.DescribeZones',
                }

                # Get listeners for this LB
                try:
                    list_listeners_req = list_lb_module.ListListenersRequest()
                    list_listeners_req.load_balancer_ids = [lb_id]
                    list_listeners_req.max_results = 100
                    listeners_resp = client.list_listeners_with_options(list_listeners_req, runtime)
                    listeners = []
                    for l in (listeners_resp.body.listeners or []):
                        listeners.append({
                            'ListenerId': getattr(l, 'listener_id', ''),
                            'ListenerPort': getattr(l, 'listener_port', 0),
                            'ListenerProtocol': getattr(l, 'listener_protocol', ''),
                            'ListenerStatus': getattr(l, 'listener_status', ''),
                            'LogConfig': str(getattr(l, 'log_config', '')),
                        })
                    item['Listeners'] = listeners
                except Exception:
                    item['Listeners'] = []

                resource_id = lb_id or f"alicloud.alb.{region}.{account_id}"
                canonical_uid = f"acs:alb:{region}:{account_id}:{resource_id}"
                item['resource_arn'] = canonical_uid
                item['resource_id'] = resource_id
                item['resource_uid'] = canonical_uid
                item['_raw_response'] = {k: v for k, v in item.items()
                                         if not k.startswith('_') and k not in
                                         ('resource_arn', 'resource_uid', 'resource_id',
                                          'resource_type', 'resource_name', 'account_id')}
                resources.append(item)
        except Exception as e:
            logger.debug("AliCloud ALB list_load_balancers/%s: %s", region, e)

        # Zones (for zone-level check rules)
        try:
            describe_zones_req = list_lb_module.DescribeZonesRequest()
            zones_resp = client.describe_zones_with_options(describe_zones_req, runtime)
            for zone in (zones_resp.body.zones or []):
                zone_id = getattr(zone, 'zone_id', '') or f"zone_{region}"
                zone_item = {
                    'id': zone_id,
                    'zone': zone_id,
                    'zone_id': zone_id,
                    'local_name': getattr(zone, 'local_name', ''),
                    'region': region,
                    'account_id': account_id,
                    'resource_type': 'alicloud.alb/Zone',
                    '_discovery_id': 'alicloud.alb.DescribeZones',
                    'resource_arn': f"acs:alb:{region}:{account_id}:zone/{zone_id}",
                    'resource_id': zone_id,
                    'resource_uid': f"acs:alb:{region}:{account_id}:zone/{zone_id}",
                }
                zone_item['_raw_response'] = {k: v for k, v in zone_item.items()
                                              if not k.startswith('_') and k not in
                                              ('resource_arn', 'resource_uid', 'resource_id',
                                               'resource_type', 'resource_name', 'account_id')}
                resources.append(zone_item)
        except Exception as e:
            logger.debug("AliCloud ALB describe_zones/%s: %s", region, e)

    except ImportError:
        logger.debug("alibabacloud_alb20200616 SDK not installed, skipping ALB scan")
    except Exception as e:
        logger.warning("AliCloud ALB scan failed [%s]: %s", region, e)
        resources = []

    logger.info("  alb/%s: %d ALB resources found", region, len(resources))
    return resources


# ─── Scanner Class ────────────────────────────────────────────────────────────

class AliCloudDiscoveryScanner(DiscoveryScanner):
    """
    AliCloud-specific discovery scanner implementation.

    Uses handler registry pattern: ALICLOUD_SERVICE_HANDLERS maps service names
    to handler functions. Add new services by decorating with @alicloud_handler.

    Credentials expected (from Secrets Manager):
        credential_type: "access_key"
        access_key_id: str
        access_key_secret: str
        account_id: str   (Alibaba Cloud UID / account ID)
    """

    def __init__(self, credentials: Dict[str, Any], **kwargs):
        super().__init__(credentials, **kwargs)
        self._access_key_id: Optional[str] = None
        self._access_key_secret: Optional[str] = None
        self._account_uid: Optional[str] = None

    def authenticate(self) -> Any:
        """Validate AliCloud access key credentials."""
        try:
            creds = self.credentials
            # Support nested credentials (Secrets Manager wrapper)
            if 'credentials' in creds and isinstance(creds['credentials'], dict):
                creds = {**creds, **creds['credentials']}

            self._access_key_id = (
                creds.get('access_key_id')
                or creds.get('AccessKeyId')
            )
            self._access_key_secret = (
                creds.get('access_key_secret')
                or creds.get('AccessKeySecret')
            )
            self._account_uid = (
                creds.get('account_id')
                or creds.get('AccountId')
                or creds.get('uid')
            )

            if not self._access_key_id or not self._access_key_secret:
                raise AuthenticationError(
                    "AliCloud credentials must include access_key_id and access_key_secret"
                )

            # Lightweight validation: list regions via ECS (no side-effects)
            from alibabacloud_ecs20140526.client import Client
            from alibabacloud_ecs20140526 import models as ecs_models
            from alibabacloud_tea_openapi import models as open_api_models

            cfg = open_api_models.Config(
                access_key_id=self._access_key_id,
                access_key_secret=self._access_key_secret,
                region_id='cn-hangzhou',
            )
            client = Client(cfg)
            client.describe_regions(ecs_models.DescribeRegionsRequest())
            logger.info("AliCloud authentication successful")
            return self._access_key_id

        except AuthenticationError:
            raise
        except Exception as e:
            logger.error("AliCloud authentication failed: %s", e)
            raise AuthenticationError(f"AliCloud authentication failed: {e}")

    async def scan_service(
        self,
        service: str,
        region: str,
        config: Dict[str, Any],
        skip_dependents: bool = False,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Execute AliCloud service discovery via registered handler."""
        handler = ALICLOUD_SERVICE_HANDLERS.get(service)
        if not handler:
            logger.warning("No AliCloud handler registered for service: %s", service)
            return ([], {'service': service, 'status': 'no_handler'})

        account_id = self._account_uid or self.credentials.get('account_id', '')
        loop = asyncio.get_event_loop()
        try:
            discoveries = await loop.run_in_executor(
                _ALICLOUD_EXECUTOR,
                handler,
                self._access_key_id,
                self._access_key_secret,
                account_id,
                region,
                config,
            )
            metadata = {
                'service': service,
                'region': region,
                'resources_found': len(discoveries),
                'status': 'completed',
            }
            return (discoveries, metadata)
        except Exception as e:
            logger.error("AliCloud %s/%s scan failed: %s", service, region, e)
            return ([], {'service': service, 'status': 'error', 'error': str(e)})

    def get_client(self, service: str, region: str) -> Any:
        """Not used directly — handlers build their own clients."""
        raise DiscoveryError("Use service handlers; AliCloud does not use a shared client")

    def extract_resource_identifier(
        self,
        item: Dict[str, Any],
        service: str,
        region: str,
        account_id: str,
        resource_type: Optional[str] = None,
    ) -> Dict[str, str]:
        """Extract resource identifiers from AliCloud response."""
        return {
            'resource_arn': item.get('resource_arn', ''),
            'resource_id': item.get('resource_id', ''),
            'resource_name': item.get('InstanceName') or item.get('BucketName') or item.get('Name') or '',
            'resource_uid': item.get('resource_uid', ''),
            'resource_type': resource_type or item.get('resource_type', ''),
        }

    def get_service_client_name(self, service: str) -> str:
        return f"alicloud.{service}"

    async def list_available_regions(self) -> List[str]:
        """Dynamically list AliCloud regions via ECS describe_regions."""
        from alibabacloud_ecs20140526.client import Client
        from alibabacloud_ecs20140526 import models as ecs_models
        from alibabacloud_tea_openapi import models as open_api_models

        cfg = open_api_models.Config(
            access_key_id=self._access_key_id,
            access_key_secret=self._access_key_secret,
            region_id='cn-hangzhou',
        )
        client = Client(cfg)
        resp = client.describe_regions(ecs_models.DescribeRegionsRequest())
        return [r.region_id for r in (resp.body.regions.region or [])]

    def get_account_id(self) -> str:
        return self._account_uid or ''
