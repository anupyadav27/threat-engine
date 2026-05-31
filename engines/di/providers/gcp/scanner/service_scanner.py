"""
GCP Discovery Scanner

Multi-cloud architecture: Uses a service handler registry pattern where each GCP
service has a registered handler. New services are added by defining a handler function
and registering it — no hardcoded if/elif chains.

Currently supported:
- iam (Global - Service Accounts)
- compute (Regional - VM Instances)
- bigquery (PaaS - Datasets)
- storage (SaaS - Buckets)

Extends to all GCP services by adding handler functions.
"""

from typing import Dict, List, Any, Optional, Tuple, Callable
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor
from common.models.provider_interface import DiscoveryScanner, AuthenticationError, DiscoveryError

# DCAT-02-G: catalog-driven emit rendering (DB-backed, mirrors AWS/K8s/Azure)
try:
    from common.jinja_renderer import render_emit_item
    _RENDERER_AVAILABLE = True
except ImportError:  # pragma: no cover
    render_emit_item = None  # type: ignore
    _RENDERER_AVAILABLE = False

logger = logging.getLogger(__name__)

# Shared failure sink (flushed by run_scan at scan completion)
_emit_failure_sink: List[Dict[str, Any]] = []

# Catalog cache: discovery_id -> emit.item template dict (or None)
_GCP_EMIT_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}
# Per-service load tracking so we only hit the DB once per service per process
_GCP_SERVICE_LOADED: set = set()


def _load_gcp_service_emits(service: str) -> None:
    """Populate _GCP_EMIT_CACHE for every discovery_id of a gcp service.

    Reads from rule_discoveries (check DB) — single source of truth, same as
    AWS / K8s / Azure. Service-default fallback added so divergent scanner
    IDs still resolve to a flat-shape template.
    """
    if service in _GCP_SERVICE_LOADED:
        return
    _GCP_SERVICE_LOADED.add(service)
    try:
        from providers.aws.aws_utils.rules import load_service_rules
        rules = load_service_rules(service, provider="gcp")
    except Exception as exc:
        logger.warning("GCP rules load failed for service=%s: %s", service, exc)
        return
    default_template: Optional[Dict[str, Any]] = None
    for disc in (rules or {}).get('discovery', []) or []:
        did = disc.get('discovery_id')
        emit = disc.get('emit') or {}
        item_tmpl = emit.get('item') if isinstance(emit, dict) else None
        valid = isinstance(item_tmpl, dict) and bool(item_tmpl)
        if did:
            _GCP_EMIT_CACHE[did] = item_tmpl if valid else None
        if valid and default_template is None:
            default_template = item_tmpl
    if default_template is not None:
        _GCP_EMIT_CACHE[f"_service_default::{service}"] = default_template


def _get_gcp_emit_template(discovery_id: str) -> Optional[Dict[str, Any]]:
    """Return cached emit.item template for a discovery_id, loading on demand.

    Falls back to the per-service default template if the exact discovery_id
    isn't in the catalog. discovery_id format: 'gcp.<service>.<resource>.<op>'.
    """
    if discovery_id in _GCP_EMIT_CACHE:
        return _GCP_EMIT_CACHE[discovery_id]
    parts = discovery_id.split('.', 2)
    if len(parts) < 2 or parts[0] != 'gcp':
        _GCP_EMIT_CACHE[discovery_id] = None
        return None
    service = parts[1]
    _load_gcp_service_emits(service)
    direct = _GCP_EMIT_CACHE.get(discovery_id)
    if direct is not None:
        return direct
    fallback = _GCP_EMIT_CACHE.get(f"_service_default::{service}")
    _GCP_EMIT_CACHE[discovery_id] = fallback
    return fallback

# Thread pool for blocking GCP SDK calls
_GCP_EXECUTOR = ThreadPoolExecutor(max_workers=10)

# Default GCP regions for scanning
DEFAULT_GCP_REGIONS = [
    'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2',
    'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4',
    'asia-east1', 'asia-southeast1', 'asia-northeast1',
    'australia-southeast1', 'southamerica-east1',
]

# ─── Service Handler Registry ──────────────────────────────────────
#
# Each handler: fn(credential, project_id, region, config) -> List[Dict]
# Add new services by defining a handler and adding to this dict.
#
GCP_SERVICE_HANDLERS: Dict[str, Callable] = {}


def gcp_handler(service_name: str):
    """Decorator to register a GCP service discovery handler."""
    def decorator(fn: Callable):
        GCP_SERVICE_HANDLERS[service_name] = fn
        return fn
    return decorator


# ─── Resource Identifier Helper ────────────────────────────────────

def _enrich_gcp_item(item: Dict) -> Dict:
    """Inject standard resource identifier fields used by database_manager.

    GCP resources use selfLink or name as primary identifier. This maps
    them to resource_arn/resource_uid/resource_id so the DB layer can
    store them correctly.

    DCAT-02-G: also renders the catalog `emit.item` template (Jinja) and
    stores the flat result on `item['emitted_fields']`. Discovery engine
    pipes this into `discovery_findings.emitted_fields` JSONB so the column
    is flat (no nested envelope objects).
    """
    self_link = item.get('selfLink', '')
    resource_id = item.get('id', '')
    # Convert GCP selfLink to canonical GCP resource name (starts with //)
    # https://www.googleapis.com/compute/v1/projects/... → //compute.googleapis.com/projects/...
    if self_link.startswith('https://www.googleapis.com/'):
        remainder = self_link[len('https://www.googleapis.com/'):]
        parts = remainder.split('/', 2)
        if len(parts) >= 3:
            api_name, _version, path = parts
            uid = f"//{api_name}.googleapis.com/{path}"
        elif len(parts) == 2:
            api_name, rest = parts
            uid = f"//{api_name}.googleapis.com/{rest}"
        else:
            uid = self_link
    elif self_link:
        uid = self_link
    elif resource_id:
        logger.warning("GCP item has no selfLink; falling back to resource_id=%r discovery_id=%s",
                       resource_id, item.get('_discovery_id'))
        uid = str(resource_id)
    else:
        discovery_id = item.get('_discovery_id', 'unknown')
        item_keys = [k for k in item.keys() if not k.startswith('_')][:10]
        logger.error("GCP_RESOURCE_ID_MISSING: discovery_id=%r item keys=%s",
                     discovery_id, item_keys)
        return None

    item['resource_arn'] = uid
    item['resource_id'] = str(resource_id) if resource_id else uid
    item['resource_uid'] = uid

    # Build _raw_response (everything except internal/metadata fields)
    item['_raw_response'] = {k: v for k, v in item.items()
                             if not k.startswith('_') and k not in (
                                 'resource_arn', 'resource_uid', 'resource_id', 'resource_type')}

    # DCAT-02-G: catalog-driven emit rendering (single chokepoint)
    if _RENDERER_AVAILABLE:
        discovery_id = item.get('_discovery_id')
        if discovery_id:
            template = _get_gcp_emit_template(discovery_id)
            if template:
                ctx = {
                    'item': item,
                    'response': item,
                    'context': {
                        'project_id': item.get('_project_id'),
                        'service': discovery_id.split('.')[1] if '.' in discovery_id else '',
                        'name': item.get('name'),
                        'self_link': self_link,
                    },
                }
                try:
                    rendered = render_emit_item(
                        template,
                        ctx,
                        discovery_id=discovery_id,
                        resource_uid=uid,
                        failure_sink=_emit_failure_sink,
                    )
                    if isinstance(rendered, dict) and rendered:
                        item['emitted_fields'] = rendered
                except Exception as exc:  # pragma: no cover
                    logger.warning(
                        "GCP emit render failed %s for %s: %s",
                        discovery_id, uid, exc,
                    )
    return item


# ─── Service Handlers ───────────────────────────────────────────────

@gcp_handler('iam')
def _scan_iam(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP IAM service accounts with enrichment.

    For each service account this emits TWO types of findings:
      1. gcp.iam.service_accounts.list — the SA itself, enriched with its
         resource-level IAM policy (bindings, audit_configs) so that check
         rules on roles/members/conditions can evaluate correctly.
      2. gcp.iam.service_account_keys.list — one finding per SA key, with
         key_algorithm / key_origin / key_type / valid_after_time / valid_before_time
         so that key-rotation check rules can evaluate correctly.
    """
    from google.cloud import iam_admin_v1
    from googleapiclient.discovery import build as gapi_build

    client = iam_admin_v1.IAMClient(credentials=credential)
    # Build REST client for getIamPolicy (not available in iam_admin_v1)
    iam_rest = gapi_build('iam', 'v1', credentials=credential, cache_discovery=False)

    service_accounts = list(
        client.list_service_accounts(
            request=iam_admin_v1.ListServiceAccountsRequest(name=f"projects/{project_id}")
        )
    )

    resources = []
    key_resources = []

    for sa in service_accounts:
        item = {
            'name': sa.name,
            'email': sa.email,
            # camelCase to match GCP REST API and check rule expectations
            'displayName': sa.display_name,
            'uniqueId': sa.unique_id,
            'description': sa.description,
            'disabled': sa.disabled,
            'oauth2ClientId': sa.oauth2_client_id,
            'projectId': sa.project_id,
            'selfLink': sa.name,
            'id': sa.unique_id,
            'resource_type': 'iam.googleapis.com/ServiceAccount',
            '_discovery_id': 'gcp.iam.service_accounts.list',
        }

        # ── Enrich: resource-level IAM policy (who can impersonate this SA) ──
        try:
            policy = iam_rest.projects().serviceAccounts().getIamPolicy(
                resource=sa.name
            ).execute()
            item['iamPolicy'] = policy
            item['bindings'] = policy.get('bindings', [])
            item['auditConfigs'] = policy.get('auditConfigs', [])
        except Exception as exc:
            logger.debug("getIamPolicy(%s) failed: %s", sa.name, exc)
            item['iamPolicy'] = {}
            item['bindings'] = []
            item['auditConfigs'] = []

        if (r := _enrich_gcp_item(item)) is not None: resources.append(r)

        # ── Emit keys as separate findings ──
        try:
            keys_req = iam_admin_v1.ListServiceAccountKeysRequest(name=sa.name)
            for key in client.list_service_account_keys(request=keys_req):
                vat = key.valid_after_time
                vbt = key.valid_before_time
                key_item = {
                    'name': key.name,
                    'selfLink': key.name,
                    'id': key.name,
                    # camelCase to match GCP REST API and check rule expectations
                    'keyAlgorithm': key.key_algorithm.name if key.key_algorithm else '',
                    'keyOrigin': key.key_origin.name if key.key_origin else '',
                    'keyType': key.key_type.name if key.key_type else '',
                    'validAfterTime': vat.isoformat() if hasattr(vat, 'isoformat') else str(vat) if vat else None,
                    'validBeforeTime': vbt.isoformat() if hasattr(vbt, 'isoformat') else str(vbt) if vbt else None,
                    'disabled': key.disabled,
                    'serviceAccountName': sa.name,
                    'serviceAccountEmail': sa.email,
                    'projectId': sa.project_id,
                    'resource_type': 'iam.googleapis.com/ServiceAccountKey',
                    '_discovery_id': 'gcp.iam.service_account_keys.list',
                }
                if (r := _enrich_gcp_item(key_item)) is not None: key_resources.append(r)
        except Exception as exc:
            logger.debug("list_service_account_keys(%s) failed: %s", sa.name, exc)

    logger.info(
        "  iam: %d service accounts (%d with policy), %d keys found",
        len(resources), sum(1 for r in resources if r.get('bindings') is not None), len(key_resources)
    )
    return resources + key_resources


@gcp_handler('compute')
def _scan_compute(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP compute instances using aggregated list (all zones).

    Emits camelCase field names matching the GCP REST API so that check rules
    using ``item.machineType``, ``item.shieldedInstanceConfig.enableSecureBoot``,
    ``item.metadata_items.enable-oslogin`` etc. evaluate correctly.

    ``metadata_items`` is a convenience flat dict built from the raw
    ``metadata.items[]`` array so check rules can do:
        var: item.metadata_items.enable-oslogin
        op: equals
        value: 'true'
    instead of needing JSONPath filter support.
    """
    from google.cloud import compute_v1

    client = compute_v1.InstancesClient(credentials=credential)
    resources = []
    agg_list = client.aggregated_list(project=project_id)
    for zone_key, instances_scoped_list in agg_list:
        if not instances_scoped_list.instances:
            continue
        # Filter by region (zone: us-central1-a → region: us-central1)
        zone_region = '-'.join(zone_key.replace('zones/', '').split('-')[:-1])
        if region and region.lower() != zone_region.lower():
            continue
        for instance in instances_scoped_list.instances:
            # ── metadata: raw array + flattened dict ──────────────────────
            raw_metadata_items = []
            metadata_items_flat: Dict[str, str] = {}
            if instance.metadata and instance.metadata.items:
                for kv in instance.metadata.items:
                    raw_metadata_items.append({'key': kv.key, 'value': kv.value})
                    metadata_items_flat[kv.key] = kv.value

            # ── shieldedInstanceConfig ────────────────────────────────────
            sic = instance.shielded_instance_config
            shielded_cfg = {
                'enableSecureBoot': sic.enable_secure_boot if sic else False,
                'enableVtpm': sic.enable_vtpm if sic else False,
                'enableIntegrityMonitoring': sic.enable_integrity_monitoring if sic else False,
            } if sic else {}

            # ── confidentialInstanceConfig ────────────────────────────────
            cic = instance.confidential_instance_config
            confidential_cfg = {
                'enableConfidentialCompute': cic.enable_confidential_compute if cic else False,
            } if cic else {}

            # ── serviceAccounts ───────────────────────────────────────────
            service_accounts = []
            for sa in (instance.service_accounts or []):
                service_accounts.append({'email': sa.email, 'scopes': list(sa.scopes or [])})

            # ── networkInterfaces ─────────────────────────────────────────
            network_interfaces = []
            for ni in (instance.network_interfaces or []):
                access_configs = []
                for ac in (ni.access_configs or []):
                    access_configs.append({
                        'type': ac.type_,
                        'name': ac.name,
                        'natIP': ac.nat_i_p,
                    })
                network_interfaces.append({
                    'name': ni.name,
                    'network': ni.network,
                    'subnetwork': ni.subnetwork,
                    'networkIP': ni.network_i_p,
                    'accessConfigs': access_configs,
                })

            item = {
                'id': str(instance.id),
                'name': instance.name,
                'selfLink': instance.self_link,
                'zone': instance.zone,
                # camelCase to match GCP REST API and check rule expectations
                'machineType': instance.machine_type,
                'status': instance.status,
                'creationTimestamp': instance.creation_timestamp,
                'canIpForward': instance.can_ip_forward,
                'deletionProtection': instance.deletion_protection,
                'labels': dict(instance.labels) if instance.labels else {},
                # metadata: raw array + flat dict for direct key checks
                'metadata': {
                    'fingerprint': instance.metadata.fingerprint if instance.metadata else '',
                    'items': raw_metadata_items,
                },
                'metadata_items': metadata_items_flat,
                # security configuration fields
                'shieldedInstanceConfig': shielded_cfg,
                'confidentialInstanceConfig': confidential_cfg,
                'serviceAccounts': service_accounts,
                'networkInterfaces': network_interfaces,
                'resource_type': 'compute.googleapis.com/Instance',
                '_discovery_id': 'gcp.compute.list_instances',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    logger.info(f"  compute/{region}: {len(resources)} instances found")
    return resources


@gcp_handler('firewall')
def _scan_firewalls(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Compute firewall rules (global — not region-specific).

    Emits camelCase field names to match check rule expectations:
      - ``logConfig.enable`` for firewall logging checks
      - ``allowed[].IPProtocol`` / ``allowed[].ports`` for port checks
      - ``sourceRanges`` for source CIDR checks
    """
    from google.cloud import compute_v1

    # Firewalls are global — only scan once (skip non-primary regions)
    if region and region not in ('us-central1', 'global', ''):
        return []

    client = compute_v1.FirewallsClient(credentials=credential)
    resources = []
    try:
        for firewall in client.list(project=project_id):
            allowed = []
            for a in (firewall.allowed or []):
                allowed.append({
                    'IPProtocol': a.I_p_protocol,
                    'ports': list(a.ports or []),
                })
            denied = []
            for d in (firewall.denied or []):
                denied.append({
                    'IPProtocol': d.I_p_protocol,
                    'ports': list(d.ports or []),
                })
            log_config = {}
            if firewall.log_config:
                log_config = {'enable': firewall.log_config.enable}

            item = {
                'id': str(firewall.id),
                'name': firewall.name,
                'selfLink': firewall.self_link,
                'network': firewall.network,
                'direction': firewall.direction,
                'priority': firewall.priority,
                'disabled': firewall.disabled,
                'allowed': allowed,
                'denied': denied,
                'sourceRanges': list(firewall.source_ranges or []),
                'destinationRanges': list(firewall.destination_ranges or []),
                'targetTags': list(firewall.target_tags or []),
                'sourceTags': list(firewall.source_tags or []),
                'logConfig': log_config,
                'resource_type': 'compute.googleapis.com/Firewall',
                '_discovery_id': 'gcp.compute.firewalls.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"  firewall/{project_id}: scan failed: {e}")
    logger.info(f"  firewall/{project_id}: {len(resources)} firewall rules found")
    return resources


@gcp_handler('vpc_network')
def _scan_vpc_networks(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP VPC networks (global resource — emits gcp.compute.networks.list)."""
    from google.cloud import compute_v1

    if region and region not in ('us-central1', 'global', ''):
        return []

    client = compute_v1.NetworksClient(credentials=credential)
    resources = []
    try:
        for network in client.list(project=project_id):
            routing_mode = 'REGIONAL'
            if network.routing_config:
                rm = network.routing_config.routing_mode
                routing_mode = rm if isinstance(rm, str) else getattr(rm, 'name', str(rm))
            peerings = [
                {
                    'name': p.name,
                    'network': p.network,
                    'state': p.state if isinstance(p.state, str) else getattr(p.state, 'name', str(p.state)),
                }
                for p in (network.peerings or [])
            ]
            item = {
                'id': str(network.id),
                'name': network.name,
                'selfLink': network.self_link,
                'autoCreateSubnetworks': network.auto_create_subnetworks,
                'subnetworks': list(network.subnetworks or []),
                'routingConfig': {'routingMode': routing_mode},
                'peerings': peerings,
                'resource_type': 'compute.googleapis.com/Network',
                '_discovery_id': 'gcp.compute.networks.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"  vpc_network/{project_id}: scan failed: {e}")
    logger.info(f"  vpc_network/{project_id}: {len(resources)} VPC networks found")
    return resources


@gcp_handler('subnetwork')
def _scan_subnetworks(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP subnets via aggregated list (emits gcp.compute.subnetworks.aggregatedList).

    Runs once per project (skipped for non-primary regions) and collects all
    subnets across all regions including enableFlowLogs for L7 analysis.
    """
    from google.cloud import compute_v1

    if region and region not in ('us-central1', 'global', ''):
        return []

    client = compute_v1.SubnetworksClient(credentials=credential)
    resources = []
    try:
        for _, region_scoped in client.aggregated_list(project=project_id):
            for subnet in (region_scoped.subnetworks or []):
                flow_logs_enabled = False
                if subnet.log_config:
                    flow_logs_enabled = subnet.log_config.enable
                item = {
                    'id': str(subnet.id),
                    'name': subnet.name,
                    'selfLink': subnet.self_link,
                    'region': subnet.region,
                    'network': subnet.network,
                    'ipCidrRange': subnet.ip_cidr_range,
                    'privateIpGoogleAccess': subnet.private_ip_google_access,
                    'enableFlowLogs': subnet.enable_flow_logs,
                    'logConfig': {'enable': flow_logs_enabled},
                    'purpose': subnet.purpose,
                    'resource_type': 'compute.googleapis.com/Subnetwork',
                    '_discovery_id': 'gcp.compute.subnetworks.aggregatedList',
                }
                if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"  subnetwork/{project_id}: scan failed: {e}")
    logger.info(f"  subnetwork/{project_id}: {len(resources)} subnets found")
    return resources


@gcp_handler('forwarding_rule')
def _scan_forwarding_rules(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP global forwarding rules / load balancers (emits gcp.compute.forwarding_rules.list)."""
    from google.cloud import compute_v1

    if region and region not in ('us-central1', 'global', ''):
        return []

    client = compute_v1.GlobalForwardingRulesClient(credentials=credential)
    resources = []
    try:
        for fr in client.list(project=project_id):
            item = {
                'id': str(fr.id),
                'name': fr.name,
                'selfLink': fr.self_link,
                'IPProtocol': fr.I_p_protocol,
                'portRange': fr.port_range,
                'loadBalancingScheme': fr.load_balancing_scheme,
                'target': fr.target,
                'networkTier': fr.network_tier,
                'IPAddress': fr.I_p_address,
                'resource_type': 'compute.googleapis.com/ForwardingRule',
                '_discovery_id': 'gcp.compute.forwarding_rules.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"  forwarding_rule/global/{project_id}: scan failed: {e}")
    logger.info(f"  forwarding_rule/{project_id}: {len(resources)} global forwarding rules found")
    return resources


@gcp_handler('route')
def _scan_routes(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP routes (global — emits gcp.compute.routes.list)."""
    from google.cloud import compute_v1

    if region and region not in ('us-central1', 'global', ''):
        return []

    client = compute_v1.RoutesClient(credentials=credential)
    resources = []
    try:
        for route in client.list(project=project_id):
            item = {
                'id': str(route.id),
                'name': route.name,
                'selfLink': route.self_link,
                'network': route.network,
                'destRange': route.dest_range,
                'nextHopGateway': route.next_hop_gateway or '',
                'nextHopIp': route.next_hop_ip or '',
                'nextHopInstance': route.next_hop_instance or '',
                'priority': route.priority,
                'resource_type': 'compute.googleapis.com/Route',
                '_discovery_id': 'gcp.compute.routes.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"  route/{project_id}: scan failed: {e}")
    logger.info(f"  route/{project_id}: {len(resources)} routes found")
    return resources


@gcp_handler('security_policy')
def _scan_security_policies(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud Armor security policies (global — emits gcp.compute.securityPolicies.list)."""
    from google.cloud import compute_v1

    if region and region not in ('us-central1', 'global', ''):
        return []

    client = compute_v1.SecurityPoliciesClient(credentials=credential)
    resources = []
    try:
        for policy in client.list(project=project_id):
            rules = []
            for rule in (policy.rules or []):
                src_ranges = []
                if rule.match and rule.match.config:
                    src_ranges = list(rule.match.config.src_ip_ranges or [])
                rules.append({
                    'priority': rule.priority,
                    'action': rule.action,
                    'preview': rule.preview,
                    'match': {'config': {'srcIpRanges': src_ranges}},
                })
            item = {
                'id': str(policy.id),
                'name': policy.name,
                'selfLink': policy.self_link,
                'type': policy.type_,
                'rules': rules,
                'resource_type': 'compute.googleapis.com/SecurityPolicy',
                '_discovery_id': 'gcp.compute.securityPolicies.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"  security_policy/{project_id}: scan failed: {e}")
    logger.info(f"  security_policy/{project_id}: {len(resources)} Cloud Armor policies found")
    return resources


@gcp_handler('bigquery')
def _scan_bigquery(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP BigQuery datasets (global — not region-specific)."""
    from google.cloud import bigquery

    client = bigquery.Client(project=project_id, credentials=credential)
    resources = []
    for dataset_ref in client.list_datasets(project=project_id):
        try:
            dataset = client.get_dataset(dataset_ref.reference)
            item = {
                'id': f"projects/{project_id}/datasets/{dataset.dataset_id}",
                'name': dataset.dataset_id,
                'selfLink': f"https://bigquery.googleapis.com/bigquery/v2/projects/{project_id}/datasets/{dataset.dataset_id}",
                'friendly_name': dataset.friendly_name,
                'description': dataset.description,
                'location': dataset.location,
                'creation_time': dataset.created.isoformat() if dataset.created else None,
                'modified_time': dataset.modified.isoformat() if dataset.modified else None,
                'default_table_expiration_ms': dataset.default_table_expiration_ms,
                'labels': dict(dataset.labels) if dataset.labels else {},
                'resource_type': 'bigquery.googleapis.com/Dataset',
                '_discovery_id': 'gcp.bigquery.datasets.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
        except Exception as e:
            logger.warning(f"Failed to get BigQuery dataset {dataset_ref.dataset_id}: {e}")
    logger.info(f"  bigquery: {len(resources)} datasets found")
    return resources


@gcp_handler('storage')
def _scan_storage(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud Storage buckets (global — not region-specific).

    Emits camelCase field names to match GCP REST API and check rule expectations:
      - ``versioning.enabled`` (not ``versioning_enabled``)
      - ``locationType`` (not ``location_type``)
      - ``retentionPolicy``, ``iamConfiguration``, ``defaultEventBasedHold``
    """
    from google.cloud import storage

    client = storage.Client(project=project_id, credentials=credential)
    resources = []
    for bucket in client.list_buckets(project=project_id):
        # ── IAM configuration ─────────────────────────────────────────────
        iam_config = getattr(bucket, 'iam_configuration', None)
        iam_configuration = {}
        if iam_config:
            iam_configuration = {
                'publicAccessPrevention': getattr(iam_config, 'public_access_prevention', None),
                'uniformBucketLevelAccess': {
                    'enabled': getattr(
                        getattr(iam_config, 'uniform_bucket_level_access', None),
                        'enabled', False
                    ),
                },
            }

        # ── Retention policy ─────────────────────────────────────────────
        rp = getattr(bucket, 'retention_policy', None)
        retention_policy = {}
        if rp:
            retention_policy = {
                'retentionPeriod': getattr(rp, 'retention_period', None),
                'effectiveTime': getattr(rp, 'effective_time', None),
                'isLocked': getattr(rp, 'is_locked', False),
            }

        item = {
            'id': bucket.id,
            'name': bucket.name,
            'selfLink': f"https://storage.googleapis.com/storage/v1/b/{bucket.name}",
            'location': bucket.location,
            # camelCase to match GCP REST API and check rule expectations
            'locationType': getattr(bucket, 'location_type', None),
            'storageClass': bucket.storage_class,
            'timeCreated': bucket.time_created.isoformat() if bucket.time_created else None,
            # versioning as nested object (matches GCP REST: {"versioning": {"enabled": true}})
            'versioning': {'enabled': bucket.versioning_enabled},
            'labels': dict(bucket.labels) if bucket.labels else {},
            'requesterPays': bucket.requester_pays,
            'defaultEventBasedHold': getattr(bucket, 'default_event_based_hold', False),
            'retentionPolicy': retention_policy,
            'iamConfiguration': iam_configuration,
            'resource_type': 'storage.googleapis.com/Bucket',
            '_discovery_id': 'gcp.storage.buckets.list',
        }
        if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    logger.info(f"  storage: {len(resources)} buckets found")
    return resources


@gcp_handler('pubsub')
def _scan_pubsub(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Pub/Sub topics (global)."""
    from google.cloud import pubsub_v1
    client = pubsub_v1.PublisherClient(credentials=credential)
    resources = []
    try:
        project_path = f"projects/{project_id}"
        for topic in client.list_topics(request={"project": project_path}):
            item = {
                'name': topic.name,
                'selfLink': topic.name,
                'id': topic.name,
                'labels': dict(topic.labels) if topic.labels else {},
                'resource_type': 'pubsub.googleapis.com/Topic',
                '_discovery_id': 'gcp.pubsub.topics.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP pubsub list_topics failed: {e}")
    logger.info(f"  pubsub: {len(resources)} topics found")
    return resources


@gcp_handler('cloudfunctions')
def _scan_cloudfunctions(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud Functions (regional)."""
    from google.cloud import functions_v1
    client = functions_v1.CloudFunctionsServiceClient(credentials=credential)
    resources = []
    try:
        parent = f"projects/{project_id}/locations/{region}"
        for fn in client.list_functions(request={"parent": parent}):
            item = {
                'name': fn.name,
                'selfLink': fn.name,
                'id': fn.name,
                'status': fn.status.name if fn.status else '',
                'runtime': fn.runtime,
                'entry_point': fn.entry_point,
                'resource_type': 'cloudfunctions.googleapis.com/CloudFunction',
                '_discovery_id': 'gcp.cloudfunctions.functions.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP cloudfunctions list ({region}) failed: {e}")
    logger.info(f"  cloudfunctions/{region}: {len(resources)} functions found")
    return resources


@gcp_handler('cloudrun')
def _scan_cloudrun(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud Run services (regional)."""
    resources = []
    try:
        from google.cloud import run_v2
        client = run_v2.ServicesClient(credentials=credential)
        parent = f"projects/{project_id}/locations/{region}"
        for svc in client.list_services(request={"parent": parent}):
            item = {
                'name': svc.name,
                'selfLink': svc.name,
                'id': svc.name,
                'uid': svc.uid,
                'resource_type': 'run.googleapis.com/Service',
                '_discovery_id': 'gcp.cloudrun.services.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP cloudrun list ({region}) failed: {e}")
    logger.info(f"  cloudrun/{region}: {len(resources)} services found")
    return resources


@gcp_handler('gke')
def _scan_gke(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP GKE clusters (regional)."""
    resources = []
    try:
        from google.cloud import container_v1
        client = container_v1.ClusterManagerClient(credentials=credential)
        parent = f"projects/{project_id}/locations/{region}"
        response = client.list_clusters(parent=parent)
        for cluster in response.clusters:
            item = {
                'name': cluster.name,
                'selfLink': cluster.self_link,
                'id': cluster.self_link or cluster.name,
                'status': cluster.status.name if cluster.status else '',
                'location': cluster.location,
                'current_node_count': cluster.current_node_count,
                'resource_type': 'container.googleapis.com/Cluster',
                '_discovery_id': 'gcp.gke.clusters.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP GKE list clusters ({region}) failed: {e}")
    logger.info(f"  gke/{region}: {len(resources)} clusters found")
    return resources


@gcp_handler('sql')
def _scan_sql(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud SQL instances (global list, filter by region)."""
    resources = []
    try:
        from googleapiclient.discovery import build
        # Use REST API for Cloud SQL (no native client library with simple list)
        service = build('sqladmin', 'v1', credentials=credential, cache_discovery=False)
        result = service.instances().list(project=project_id).execute()
        for instance in result.get('items', []):
            if instance.get('region', '') != region:
                continue
            item = {
                'name': instance.get('name', ''),
                'selfLink': instance.get('selfLink', ''),
                'id': instance.get('selfLink', instance.get('name', '')),
                'databaseVersion': instance.get('databaseVersion', ''),
                'state': instance.get('state', ''),
                'region': instance.get('region', ''),
                'resource_type': 'sqladmin.googleapis.com/Instance',
                '_discovery_id': 'gcp.sql.instances.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Cloud SQL list ({region}) failed: {e}")
    logger.info(f"  sql/{region}: {len(resources)} instances found")
    return resources


@gcp_handler('dns')
def _scan_dns(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud DNS managed zones (global)."""
    resources = []
    try:
        from google.cloud import dns as gcp_dns
        client = gcp_dns.Client(project=project_id, credentials=credential)
        for zone in client.list_zones():
            item = {
                'name': zone.name,
                'selfLink': zone.self_link or f"projects/{project_id}/managedZones/{zone.name}",
                'id': zone.name,
                'dns_name': zone.dns_name,
                'description': zone.description,
                'visibility': zone.visibility,
                'resource_type': 'dns.googleapis.com/ManagedZone',
                '_discovery_id': 'gcp.dns.zones.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Cloud DNS list_zones failed: {e}")
    logger.info(f"  dns: {len(resources)} zones found")
    return resources


@gcp_handler('secretmanager')
def _scan_secretmanager(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Secret Manager secrets (global)."""
    resources = []
    try:
        from google.cloud import secretmanager
        client = secretmanager.SecretManagerServiceClient(credentials=credential)
        parent = f"projects/{project_id}"
        for secret in client.list_secrets(request={"parent": parent}):
            item = {
                'name': secret.name,
                'selfLink': secret.name,
                'id': secret.name,
                'labels': dict(secret.labels) if secret.labels else {},
                'resource_type': 'secretmanager.googleapis.com/Secret',
                '_discovery_id': 'gcp.secretmanager.secrets.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Secret Manager list_secrets failed: {e}")
    logger.info(f"  secretmanager: {len(resources)} secrets found")
    return resources


@gcp_handler('logging')
def _scan_logging(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud Logging sinks and metrics."""
    resources = []
    try:
        from google.cloud import logging_v2
        client = logging_v2.ConfigServiceV2Client(credentials=credential)
        parent = f"projects/{project_id}"
        # Log sinks
        for sink in client.list_sinks(request={"parent": parent}):
            item = {
                'name': sink.name,
                'selfLink': sink.name,
                'id': sink.name,
                'destination': sink.destination,
                'filter': sink.filter,
                'resource_type': 'logging.googleapis.com/LogSink',
                '_discovery_id': 'gcp.logging.sinks.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Logging list_sinks failed: {e}")
    try:
        from google.cloud import logging_v2
        metrics_client = logging_v2.MetricsServiceV2Client(credentials=credential)
        parent = f"projects/{project_id}"
        # Log metrics
        for metric in metrics_client.list_log_metrics(request={"parent": parent}):
            item = {
                'name': metric.name,
                'selfLink': metric.name,
                'id': metric.name,
                'description': metric.description,
                'filter': metric.filter,
                'resource_type': 'logging.googleapis.com/LogMetric',
                '_discovery_id': 'gcp.logging.metrics.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Logging list_log_metrics failed: {e}")
    logger.info(f"  logging: {len(resources)} sinks+metrics found")
    return resources


@gcp_handler('monitoring')
def _scan_monitoring(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud Monitoring alert policies."""
    resources = []
    try:
        from google.cloud import monitoring_v3
        client = monitoring_v3.AlertPolicyServiceClient(credentials=credential)
        name = f"projects/{project_id}"
        for policy in client.list_alert_policies(request={"name": name}):
            item = {
                'name': policy.name,
                'selfLink': policy.name,
                'id': policy.name,
                'display_name': policy.display_name,
                'enabled': policy.enabled.value if policy.enabled else None,
                'resource_type': 'monitoring.googleapis.com/AlertPolicy',
                '_discovery_id': 'gcp.monitoring.alert_policies.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Monitoring list_alert_policies failed: {e}")
    logger.info(f"  monitoring: {len(resources)} alert policies found")
    return resources


@gcp_handler('cloudkms')
def _scan_cloudkms(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud KMS key rings (regional)."""
    resources = []
    try:
        from google.cloud import kms
        client = kms.KeyManagementServiceClient(credentials=credential)
        location = f"projects/{project_id}/locations/{region}"
        for key_ring in client.list_key_rings(request={"parent": location}):
            item = {
                'name': key_ring.name,
                'selfLink': key_ring.name,
                'id': key_ring.name,
                'create_time': key_ring.create_time.isoformat() if key_ring.create_time else None,
                'resource_type': 'cloudkms.googleapis.com/KeyRing',
                '_discovery_id': 'gcp.cloudkms.key_rings.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP KMS list_key_rings ({region}) failed: {e}")
    logger.info(f"  cloudkms/{region}: {len(resources)} key rings found")
    return resources


@gcp_handler('spanner')
def _scan_spanner(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Spanner instances (global)."""
    resources = []
    try:
        from google.cloud import spanner_v1
        client = spanner_v1.InstanceAdminClient(credentials=credential)
        parent = f"projects/{project_id}"
        for instance in client.list_instances(request={"parent": parent}):
            item = {
                'name': instance.name,
                'selfLink': instance.name,
                'id': instance.name,
                'display_name': instance.display_name,
                'config': instance.config,
                'node_count': instance.node_count,
                'state': instance.state.name if instance.state else '',
                'labels': dict(instance.labels) if instance.labels else {},
                'resource_type': 'spanner.googleapis.com/Instance',
                '_discovery_id': 'gcp.spanner.instances.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Spanner list_instances failed: {e}")
    logger.info(f"  spanner: {len(resources)} instances found")
    return resources


@gcp_handler('firestore')
def _scan_firestore(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Firestore databases (global)."""
    resources = []
    try:
        from google.cloud import firestore_admin_v1
        client = firestore_admin_v1.FirestoreAdminClient(credentials=credential)
        parent = f"projects/{project_id}"
        for db in client.list_databases(request={"parent": parent}):
            item = {
                'name': db.name,
                'selfLink': db.name,
                'id': db.name,
                'type': db.type_.name if db.type_ else '',
                'location_id': db.location_id,
                'resource_type': 'firestore.googleapis.com/Database',
                '_discovery_id': 'gcp.firestore.databases.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Firestore list_databases failed: {e}")
    logger.info(f"  firestore: {len(resources)} databases found")
    return resources


@gcp_handler('artifactregistry')
def _scan_artifactregistry(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Artifact Registry repositories (regional)."""
    resources = []
    try:
        from google.cloud import artifactregistry_v1
        client = artifactregistry_v1.ArtifactRegistryClient(credentials=credential)
        parent = f"projects/{project_id}/locations/{region}"
        for repo in client.list_repositories(request={"parent": parent}):
            item = {
                'name': repo.name,
                'selfLink': repo.name,
                'id': repo.name,
                'format': repo.format_.name if repo.format_ else '',
                'description': repo.description,
                'labels': dict(repo.labels) if repo.labels else {},
                'resource_type': 'artifactregistry.googleapis.com/Repository',
                '_discovery_id': 'gcp.artifactregistry.repositories.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP ArtifactRegistry list_repositories ({region}) failed: {e}")
    logger.info(f"  artifactregistry/{region}: {len(resources)} repositories found")
    return resources


@gcp_handler('workflows')
def _scan_workflows(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Workflows (regional)."""
    resources = []
    try:
        from google.cloud import workflows_v1
        client = workflows_v1.WorkflowsClient(credentials=credential)
        parent = f"projects/{project_id}/locations/{region}"
        for workflow in client.list_workflows(request={"parent": parent}):
            item = {
                'name': workflow.name,
                'selfLink': workflow.name,
                'id': workflow.name,
                'description': workflow.description,
                'state': workflow.state.name if workflow.state else '',
                'resource_type': 'workflows.googleapis.com/Workflow',
                '_discovery_id': 'gcp.workflows.workflows.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Workflows list_workflows ({region}) failed: {e}")
    logger.info(f"  workflows/{region}: {len(resources)} workflows found")
    return resources


@gcp_handler('dlp')
def _scan_dlp(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP DLP inspect templates (global)."""
    resources = []
    try:
        from google.cloud import dlp_v2
        client = dlp_v2.DlpServiceClient(credentials=credential)
        parent = f"projects/{project_id}"
        for template in client.list_inspect_templates(request={"parent": parent}):
            item = {
                'name': template.name,
                'selfLink': template.name,
                'id': template.name,
                'display_name': template.display_name,
                'description': template.description,
                'resource_type': 'dlp.googleapis.com/InspectTemplate',
                '_discovery_id': 'gcp.dlp.inspect_templates.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP DLP list_inspect_templates failed: {e}")
    logger.info(f"  dlp: {len(resources)} inspect templates found")
    return resources


@gcp_handler('filestore')
def _scan_filestore(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Filestore instances (regional)."""
    resources = []
    try:
        from google.cloud import filestore_v1
        client = filestore_v1.CloudFilestoreManagerClient(credentials=credential)
        parent = f"projects/{project_id}/locations/{region}"
        for instance in client.list_instances(request={"parent": parent}):
            item = {
                'name': instance.name,
                'selfLink': instance.name,
                'id': instance.name,
                'description': instance.description,
                'state': instance.state.name if instance.state else '',
                'tier': instance.tier.name if instance.tier else '',
                'resource_type': 'file.googleapis.com/Instance',
                '_discovery_id': 'gcp.filestore.instances.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Filestore list_instances ({region}) failed: {e}")
    logger.info(f"  filestore/{region}: {len(resources)} instances found")
    return resources


@gcp_handler('dataflow')
def _scan_dataflow(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Dataflow jobs (regional)."""
    resources = []
    try:
        from google.cloud import dataflow_v1beta3
        client = dataflow_v1beta3.JobsV1Beta3Client(credentials=credential)
        for job in client.list_jobs(request={"project_id": project_id, "location": region}):
            item = {
                'name': job.name,
                'selfLink': job.id,
                'id': job.id,
                'project_id': job.project_id,
                'current_state': job.current_state.name if job.current_state else '',
                'type': job.type_.name if job.type_ else '',
                'resource_type': 'dataflow.googleapis.com/Job',
                '_discovery_id': 'gcp.dataflow.jobs.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Dataflow list_jobs ({region}) failed: {e}")
    logger.info(f"  dataflow/{region}: {len(resources)} jobs found")
    return resources


@gcp_handler('apikeys')
def _scan_apikeys(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP API Keys (global)."""
    resources = []
    try:
        from google.cloud import api_keys_v2
        client = api_keys_v2.ApiKeysClient(credentials=credential)
        parent = f"projects/{project_id}/locations/global"
        for key in client.list_keys(request={"parent": parent}):
            item = {
                'name': key.name,
                'selfLink': key.name,
                'id': key.name,
                'display_name': key.display_name,
                'uid': key.uid,
                'resource_type': 'apikeys.googleapis.com/Key',
                '_discovery_id': 'gcp.apikeys.keys.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP API Keys list_keys failed: {e}")
    logger.info(f"  apikeys: {len(resources)} keys found")
    return resources


@gcp_handler('iam_roles')
def _scan_iam_roles(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP custom IAM roles for a project (global — not region-specific).

    Emits one finding per role with included_permissions so that check rules
    on role permissions (excessive permissions, admin privileges, SoD) can evaluate.
    Also emits predefined roles that appear in the project IAM policy bindings.
    """
    resources = []
    try:
        from googleapiclient.discovery import build as gapi_build
        iam_rest = gapi_build('iam', 'v1', credentials=credential, cache_discovery=False)

        # List custom roles defined in this project
        page_token = None
        while True:
            resp = iam_rest.projects().roles().list(
                parent=f"projects/{project_id}",
                showDeleted=False,
                pageToken=page_token,
            ).execute()
            for role in resp.get('roles', []):
                item = {
                    'name': role.get('name', ''),
                    'selfLink': role.get('name', ''),
                    'id': role.get('name', ''),
                    'title': role.get('title', ''),
                    'description': role.get('description', ''),
                    'stage': role.get('stage', 'GA'),
                    'included_permissions': role.get('includedPermissions', []),
                    'etag': role.get('etag', ''),
                    'deleted': role.get('deleted', False),
                    'resource_type': 'iam.googleapis.com/Role',
                    '_discovery_id': 'gcp.iam.roles.list',
                }
                if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
            page_token = resp.get('nextPageToken')
            if not page_token:
                break
    except Exception as e:
        logger.warning(f"GCP IAM roles list failed: {e}")
    logger.info(f"  iam_roles: {len(resources)} custom roles found")
    return resources


@gcp_handler('notebooks')
def _scan_notebooks(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Notebooks instances (regional)."""
    resources = []
    try:
        from google.cloud import notebooks_v1
        client = notebooks_v1.NotebookServiceClient(credentials=credential)
        parent = f"projects/{project_id}/locations/{region}"
        for instance in client.list_instances(request={"parent": parent}):
            item = {
                'name': instance.name,
                'selfLink': instance.name,
                'id': instance.name,
                'state': instance.state.name if instance.state else '',
                'vm_image': str(instance.vm_image) if hasattr(instance, 'vm_image') else '',
                'resource_type': 'notebooks.googleapis.com/Instance',
                '_discovery_id': 'gcp.notebooks.instances.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Notebooks list_instances ({region}) failed: {e}")
    logger.info(f"  notebooks/{region}: {len(resources)} instances found")
    return resources


@gcp_handler('bigtable')
def _scan_bigtable(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Bigtable instances (global)."""
    resources = []
    try:
        from google.cloud import bigtable
        client = bigtable.Client(project=project_id, credentials=credential, admin=True)
        for instance in client.list_instances()[0]:
            item = {
                'name': instance.instance_id,
                'selfLink': instance.name,
                'id': instance.name,
                'display_name': instance.display_name,
                'type': instance.type_.name if instance.type_ else '',
                'state': instance.state.name if instance.state else '',
                'labels': dict(instance.labels) if instance.labels else {},
                'resource_type': 'bigtableadmin.googleapis.com/Instance',
                '_discovery_id': 'gcp.bigtable.instances.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Bigtable list_instances failed: {e}")
    logger.info(f"  bigtable: {len(resources)} instances found")
    return resources


@gcp_handler('resourcemanager')
def _scan_resourcemanager(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP projects via Resource Manager (org-level)."""
    resources = []
    try:
        from google.cloud import resourcemanager_v3
        client = resourcemanager_v3.ProjectsClient(credentials=credential)
        for project in client.list_projects(request={"parent": f"projects/{project_id}"}):
            item = {
                'name': project.name,
                'selfLink': project.name,
                'id': project.project_id,
                'display_name': project.display_name,
                'state': project.state.name if project.state else '',
                'labels': dict(project.labels) if project.labels else {},
                'resource_type': 'cloudresourcemanager.googleapis.com/Project',
                '_discovery_id': 'gcp.resourcemanager.projects.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Resource Manager list_projects failed: {e}")
    logger.info(f"  resourcemanager: {len(resources)} projects found")
    return resources


@gcp_handler('cloudsql')
def _scan_cloudsql(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud SQL instances (alias for 'sql' using sqladmin REST API)."""
    resources = []
    try:
        from googleapiclient.discovery import build
        service = build('sqladmin', 'v1', credentials=credential, cache_discovery=False)
        result = service.instances().list(project=project_id).execute()
        for instance in result.get('items', []):
            item = {
                'name': instance.get('name', ''),
                'selfLink': instance.get('selfLink', ''),
                'id': instance.get('selfLink', instance.get('name', '')),
                'databaseVersion': instance.get('databaseVersion', ''),
                'state': instance.get('state', ''),
                'region': instance.get('region', ''),
                'backendType': instance.get('backendType', ''),
                'settings': instance.get('settings', {}),
                'resource_type': 'sqladmin.googleapis.com/Instance',
                '_discovery_id': 'gcp.cloudsql.instances.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Cloud SQL (cloudsql) list failed: {e}")
    logger.info(f"  cloudsql: {len(resources)} instances found")
    return resources


@gcp_handler('aiplatform')
def _scan_aiplatform(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Vertex AI / AI Platform datasets and models (regional)."""
    resources = []
    try:
        from google.cloud import aiplatform_v1
        parent = f"projects/{project_id}/locations/{region}"
        ds_client = aiplatform_v1.DatasetServiceClient(credentials=credential)
        for ds in ds_client.list_datasets(parent=parent):
            item = {
                'name': ds.name, 'selfLink': ds.name, 'id': ds.name,
                'display_name': ds.display_name,
                'metadata_schema_uri': ds.metadata_schema_uri,
                'resource_type': 'aiplatform.googleapis.com/Dataset',
                '_discovery_id': 'gcp.aiplatform.datasets.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
        model_client = aiplatform_v1.ModelServiceClient(credentials=credential)
        for model in model_client.list_models(parent=parent):
            item = {
                'name': model.name, 'selfLink': model.name, 'id': model.name,
                'display_name': model.display_name,
                'version_id': model.version_id,
                'resource_type': 'aiplatform.googleapis.com/Model',
                '_discovery_id': 'gcp.aiplatform.models.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP AI Platform list ({region}) failed: {e}")
    logger.info(f"  aiplatform/{region}: {len(resources)} resources found")
    return resources


@gcp_handler('backupdr')
def _scan_backupdr(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Backup and DR backup vaults (regional)."""
    resources = []
    try:
        from google.cloud import backupdr_v1
        client = backupdr_v1.BackupDRClient(credentials=credential)
        parent = f"projects/{project_id}/locations/{region}"
        for vault in client.list_backup_vaults(parent=parent):
            item = {
                'name': vault.name, 'selfLink': vault.name, 'id': vault.name,
                'state': vault.state.name if vault.state else '',
                'resource_type': 'backupdr.googleapis.com/BackupVault',
                '_discovery_id': 'gcp.backupdr.backup_vaults.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Backup DR list ({region}) failed: {e}")
    logger.info(f"  backupdr/{region}: {len(resources)} vaults found")
    return resources


@gcp_handler('billing')
def _scan_billing(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP billing accounts (global — only runs once)."""
    if region not in ('us-central1', 'global'):
        return []
    resources = []
    try:
        from google.cloud import billing_v1
        client = billing_v1.CloudBillingClient(credentials=credential)
        for account in client.list_billing_accounts():
            item = {
                'name': account.name, 'selfLink': account.name, 'id': account.name,
                'display_name': account.display_name,
                'open': account.open_,
                'resource_type': 'billing.googleapis.com/BillingAccount',
                '_discovery_id': 'gcp.billing.billing_accounts.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Billing list failed: {e}")
    logger.info(f"  billing: {len(resources)} accounts found")
    return resources


@gcp_handler('osconfig')
def _scan_osconfig(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP OS Config patch deployments (regional)."""
    resources = []
    try:
        from google.cloud import osconfig_v1
        client = osconfig_v1.OsConfigServiceClient(credentials=credential)
        parent = f"projects/{project_id}"
        for patch in client.list_patch_deployments(parent=parent):
            item = {
                'name': patch.name, 'selfLink': patch.name, 'id': patch.name,
                'description': patch.description,
                'resource_type': 'osconfig.googleapis.com/PatchDeployment',
                '_discovery_id': 'gcp.osconfig.patch_deployments.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP OS Config list failed: {e}")
    logger.info(f"  osconfig: {len(resources)} patch deployments found")
    return resources


@gcp_handler('asset')
def _scan_asset(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud Asset feeds (global — only runs once)."""
    if region not in ('us-central1', 'global'):
        return []
    resources = []
    try:
        from google.cloud import asset_v1
        client = asset_v1.AssetServiceClient(credentials=credential)
        parent = f"projects/{project_id}"
        for feed in client.list_feeds(parent=parent).feeds:
            item = {
                'name': feed.name, 'selfLink': feed.name, 'id': feed.name,
                'asset_types': list(feed.asset_types),
                'resource_type': 'cloudasset.googleapis.com/Feed',
                '_discovery_id': 'gcp.asset.feeds.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Asset feeds list failed: {e}")
    logger.info(f"  asset: {len(resources)} feeds found")
    return resources


@gcp_handler('endpoints')
def _scan_endpoints(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud Endpoints / Service Management services (global)."""
    if region not in ('us-central1', 'global'):
        return []
    resources = []
    try:
        from googleapiclient.discovery import build
        service = build('servicemanagement', 'v1', credentials=credential, cache_discovery=False)
        result = service.services().list(producerProjectId=project_id).execute()
        for svc in result.get('services', []):
            item = {
                'name': svc.get('serviceName', ''),
                'selfLink': svc.get('serviceName', ''),
                'id': svc.get('serviceName', ''),
                'producer_project_id': svc.get('producerProjectId', ''),
                'resource_type': 'servicemanagement.googleapis.com/Service',
                '_discovery_id': 'gcp.endpoints.services.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Endpoints list failed: {e}")
    logger.info(f"  endpoints: {len(resources)} services found")
    return resources


@gcp_handler('trace')
def _scan_trace(credential, project_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover GCP Cloud Trace traces (global — only runs once)."""
    if region not in ('us-central1', 'global'):
        return []
    resources = []
    try:
        from googleapiclient.discovery import build
        service = build('cloudtrace', 'v2', credentials=credential, cache_discovery=False)
        result = service.projects().traces().list(parent=f"projects/{project_id}").execute()
        for trace in result.get('traces', []):
            item = {
                'name': trace.get('name', ''),
                'selfLink': trace.get('name', ''),
                'id': trace.get('name', ''),
                'resource_type': 'cloudtrace.googleapis.com/Trace',
                '_discovery_id': 'gcp.trace.traces.list',
            }
            if (r := _enrich_gcp_item(item)) is not None: resources.append(r)
    except Exception as e:
        logger.warning(f"GCP Trace list failed: {e}")
    logger.info(f"  trace: {len(resources)} traces found")
    return resources


# ─── Main Scanner Class ─────────────────────────────────────────────

class GCPDiscoveryScanner(DiscoveryScanner):
    """
    GCP-specific discovery scanner implementation.

    Uses a handler registry pattern: GCP_SERVICE_HANDLERS maps service names
    to handler functions. To add a new GCP service, just define a handler
    function with the @gcp_handler('service_name') decorator above.
    """

    def __init__(self, credentials: Dict[str, Any], **kwargs):
        super().__init__(credentials, **kwargs)
        self.credential = None
        # Extract project_id — check nested SA JSON first (most authoritative).
        # account_id at top level is the internal UUID from Secrets Manager wrapper,
        # NOT the GCP project ID, so it must be the last resort.
        self.project_id = (
            credentials.get('project_id')
            or (credentials.get('credentials') or {}).get('project_id')
            or credentials.get('account_id')
        )

    def authenticate(self) -> Any:
        """
        Authenticate to GCP using provided credentials.

        Supports:
        - Service Account (JSON key file)
        - Workload Identity
        - Application Default Credentials (gcloud CLI auth)
        """
        try:
            cred_type = self.credentials.get('credential_type', '').lower()

            if cred_type in ('service_account', 'gcp_service_account'):
                from google.oauth2 import service_account
                # Support multiple credential formats:
                # 1. {"credentials_json": {...}}
                # 2. {"service_account_json": {...}}
                # 3. {"credentials": {...}}  (Secrets Manager wrapper format)
                # 4. Direct SA JSON with "type": "service_account" at top level
                credentials_data = (
                    self.credentials.get('credentials_json')
                    or self.credentials.get('service_account_json')
                    or self.credentials.get('credentials')
                )
                if not credentials_data and self.credentials.get('type') == 'service_account':
                    credentials_data = self.credentials
                if isinstance(credentials_data, str):
                    import json
                    credentials_data = json.loads(credentials_data)
                self.credential = service_account.Credentials.from_service_account_info(
                    credentials_data
                )
                # SA JSON is the authoritative source for project_id — always prefer it.
                if credentials_data and credentials_data.get('project_id'):
                    self.project_id = credentials_data.get('project_id')
                logger.info("GCP authentication successful (Service Account)")

            elif cred_type == 'application_default':
                import google.auth
                self.credential, default_project = google.auth.default()
                if not self.project_id:
                    self.project_id = default_project
                logger.info(f"GCP authentication successful (Application Default, project={self.project_id})")

            else:
                import google.auth
                self.credential, default_project = google.auth.default()
                if not self.project_id:
                    self.project_id = default_project
                logger.info(f"GCP auth: unknown type '{cred_type}', using Application Default (project={self.project_id})")

            return self.credential

        except Exception as e:
            logger.error(f"GCP authentication failed: {e}")
            raise AuthenticationError(f"GCP authentication failed: {e}")

    async def scan_service(
        self,
        service: str,
        region: str,
        config: Dict[str, Any],
        skip_dependents: bool = False,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Execute GCP service discovery.

        Dispatches to the registered handler for the service.
        Runs GCP SDK calls in a thread pool (SDK is blocking).
        Returns (discoveries, scan_metadata) tuple.
        """
        handler = GCP_SERVICE_HANDLERS.get(service)
        if not handler:
            logger.warning(f"GCP: no handler registered for service '{service}'. "
                           f"Available: {list(GCP_SERVICE_HANDLERS.keys())}")
            return [], {'service': service, 'region': region, 'error': f'No handler for {service}'}

        loop = asyncio.get_event_loop()
        try:
            discoveries = await loop.run_in_executor(
                _GCP_EXECUTOR,
                handler,
                self.credential,
                self.project_id,
                region,
                config
            )
            scan_metadata = {
                'service': service,
                'region': region,
                'resource_count': len(discoveries),
                'provider': 'gcp',
            }
            logger.info(f"GCP {service}/{region}: {len(discoveries)} resources discovered")
            return discoveries, scan_metadata

        except Exception as e:
            logger.error(f"GCP scan_service failed for {service}/{region}: {e}")
            return [], {'service': service, 'region': region, 'error': str(e)}

    def get_client(self, service: str, region: str) -> Any:
        """Get GCP SDK client for specific service."""
        if service == 'iam':
            from google.cloud import iam_admin_v1
            return iam_admin_v1.IAMClient(credentials=self.credential)
        elif service == 'compute':
            from google.cloud import compute_v1
            return compute_v1.InstancesClient(credentials=self.credential)
        elif service == 'bigquery':
            from google.cloud import bigquery
            return bigquery.Client(project=self.project_id, credentials=self.credential)
        elif service == 'storage':
            from google.cloud import storage
            return storage.Client(project=self.project_id, credentials=self.credential)
        elif service == 'pubsub':
            from google.cloud import pubsub_v1
            return pubsub_v1.PublisherClient(credentials=self.credential)
        elif service == 'secretmanager':
            from google.cloud import secretmanager
            return secretmanager.SecretManagerServiceClient(credentials=self.credential)
        elif service == 'cloudkms':
            from google.cloud import kms
            return kms.KeyManagementServiceClient(credentials=self.credential)
        elif service == 'spanner':
            from google.cloud import spanner_v1
            return spanner_v1.InstanceAdminClient(credentials=self.credential)
        elif service == 'firestore':
            from google.cloud import firestore_admin_v1
            return firestore_admin_v1.FirestoreAdminClient(credentials=self.credential)
        elif service == 'artifactregistry':
            from google.cloud import artifactregistry_v1
            return artifactregistry_v1.ArtifactRegistryClient(credentials=self.credential)
        elif service == 'workflows':
            from google.cloud import workflows_v1
            return workflows_v1.WorkflowsClient(credentials=self.credential)
        elif service == 'dlp':
            from google.cloud import dlp_v2
            return dlp_v2.DlpServiceClient(credentials=self.credential)
        elif service == 'filestore':
            from google.cloud import filestore_v1
            return filestore_v1.CloudFilestoreManagerClient(credentials=self.credential)
        elif service == 'dataflow':
            from google.cloud import dataflow_v1beta3
            return dataflow_v1beta3.JobsV1Beta3Client(credentials=self.credential)
        elif service == 'apikeys':
            from google.cloud import api_keys_v2
            return api_keys_v2.ApiKeysClient(credentials=self.credential)
        elif service == 'notebooks':
            from google.cloud import notebooks_v1
            return notebooks_v1.NotebookServiceClient(credentials=self.credential)
        elif service == 'bigtable':
            from google.cloud import bigtable
            return bigtable.Client(project=self.project_id, credentials=self.credential, admin=True)
        elif service == 'resourcemanager':
            from google.cloud import resourcemanager_v3
            return resourcemanager_v3.ProjectsClient(credentials=self.credential)
        elif service == 'monitoring':
            from google.cloud import monitoring_v3
            return monitoring_v3.AlertPolicyServiceClient(credentials=self.credential)
        elif service == 'logging':
            from google.cloud import logging_v2
            return logging_v2.ConfigServiceV2Client(credentials=self.credential)
        else:
            raise DiscoveryError(f"Unsupported GCP service: {service}")

    def extract_resource_identifier(
        self,
        item: Dict[str, Any],
        service: str,
        region: str,
        account_id: str,
        resource_type: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Extract resource identifiers from GCP response.

        GCP uses selfLink format:
        https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{name}
        """
        self_link = item.get('selfLink', '')
        resource_name = item.get('name', '')
        resource_id = item.get('id', '')
        if not resource_type:
            resource_type = item.get('resource_type', '')

        # Canonical GCP resource name (// prefix)
        if self_link.startswith('https://www.googleapis.com/'):
            remainder = self_link[len('https://www.googleapis.com/'):]
            parts = remainder.split('/', 2)
            if len(parts) >= 3:
                api_name, _version, path = parts
                canonical_uid = f"//{api_name}.googleapis.com/{path}"
            else:
                canonical_uid = self_link
        elif self_link:
            canonical_uid = self_link
        else:
            canonical_uid = str(resource_id)

        return {
            'resource_arn': canonical_uid,
            'resource_id': str(resource_id) if resource_id else self_link,
            'resource_name': resource_name,
            'resource_uid': canonical_uid,
            'resource_type': resource_type,
        }

    def get_service_client_name(self, service: str) -> str:
        """Map service name to GCP SDK client name."""
        mapping = {
            'iam': 'iam_admin_v1',
            'compute': 'compute_v1',
            'bigquery': 'bigquery',
            'storage': 'storage',
        }
        return mapping.get(service, f"{service}_v1")

    async def list_available_regions(self) -> List[str]:
        """List available GCP regions for the project."""
        from google.cloud import compute_v1
        client = compute_v1.RegionsClient(credentials=self.credential)
        regions = []
        for region in client.list(project=self.project_id):
            if region.status == 'UP':
                regions.append(region.name)
        logger.info(f"GCP: {len(regions)} regions available")
        return sorted(regions)

    def get_account_id(self) -> str:
        """Return project ID as account identifier."""
        return self.project_id or ''
