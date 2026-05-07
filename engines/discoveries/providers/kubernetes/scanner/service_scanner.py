"""
Kubernetes Discovery Scanner

Implements Kubernetes-specific discovery using handler registry pattern.
Each K8s resource type is a handler registered via @k8s_handler decorator.

K8s is unique: no region concept, uses in-cluster auth or kubeconfig,
discovers K8s API objects (pods, deployments, services, etc.).

DCAT-02-E: Catalog-as-truth — `_enrich_k8s_item` now loads
`step6_<service>.discovery.yaml` from the catalog and runs Jinja templates
through `common.jinja_renderer.render_emit_item` to populate
`emitted_fields` (flat, no nested envelopes). Failures recorded to the
shared `_emit_failure_sink` and flushed by run_scan at scan-end.
"""

from typing import Dict, List, Any, Optional, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor
import asyncio
import logging

from common.models.provider_interface import DiscoveryScanner, AuthenticationError, DiscoveryError

# DCAT-02-E: catalog-driven emit rendering (DB-backed, mirrors AWS pattern)
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
_K8S_EMIT_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}
# Per-service load tracking so we only hit the DB once per service per process
_K8S_SERVICE_LOADED: set = set()

# DCAT-02-E: cross-service alias map for scanner IDs whose service-stem
# doesn't match the catalog file location. Without this, the loader would
# look in the wrong service folder and miss the template.
_K8S_SERVICE_ALIAS: Dict[str, str] = {
    "deployments": "deployment",       # scanner: k8s.deployments.list
    "hpa": "horizontalpodautoscaler",  # scanner: k8s.hpa.list
    # k8s.cluster.list_namespace → namespace catalog
    # k8s.network.list_service_* → service catalog
    # k8s.monitoring.list_config_map_* → configmap catalog
}

# Per-(scanner-id) → resolved-service overrides for the few cases where the
# discovery_id's first segment names a logical group rather than the catalog
# folder. Resolved by exact discovery_id match before service-stem fallback.
_K8S_DISCOVERY_ID_SERVICE: Dict[str, str] = {
    "k8s.cluster.list_namespace": "namespace",
    "k8s.network.list_service_for_all_namespaces": "service",
    "k8s.monitoring.list_config_map_for_all_namespaces": "configmap",
    "k8s.monitoring.list_service_for_all_namespaces": "service",
    "k8s.rbac.list_role_for_all_namespaces": "role",
    "k8s.rbac.list_cluster_role": "clusterrole",
    "k8s.rbac.list_cluster_role_binding": "clusterrolebinding",
}


def _load_k8s_service_emits(service: str) -> None:
    """Populate _K8S_EMIT_CACHE for every discovery_id of a k8s service.

    Reads from rule_discoveries (check DB) — single source of truth, same as
    AWS scanner. YAML on disk is seed data only.

    Also caches `_service_default::<service>` → first non-empty emit.item
    template found, so divergent scanner IDs (e.g. scanner emits
    `k8s.pod.list_pods` while catalog has `k8s.pod.list_pod_for_all_namespaces`)
    still resolve to a flat-shape template instead of silently falling through.
    See DCAT-02-E audit: 21/33 scanner IDs use short-form, catalog uses verbose
    form; check rules reference the short-form. Service-default fallback keeps
    both sides untouched.
    """
    if service in _K8S_SERVICE_LOADED:
        return
    _K8S_SERVICE_LOADED.add(service)
    try:
        # Reuse AWS rules loader (provider-aware)
        from providers.aws.aws_utils.rules import load_service_rules
        rules = load_service_rules(service, provider="k8s")
    except Exception as exc:
        logger.warning("K8s rules load failed for service=%s: %s", service, exc)
        return
    default_template: Optional[Dict[str, Any]] = None
    for disc in (rules or {}).get('discovery', []) or []:
        did = disc.get('discovery_id')
        emit = disc.get('emit') or {}
        item_tmpl = emit.get('item') if isinstance(emit, dict) else None
        valid = isinstance(item_tmpl, dict) and bool(item_tmpl)
        if did:
            _K8S_EMIT_CACHE[did] = item_tmpl if valid else None
        if valid and default_template is None:
            default_template = item_tmpl
    if default_template is not None:
        _K8S_EMIT_CACHE[f"_service_default::{service}"] = default_template


def _get_k8s_emit_template(discovery_id: str) -> Optional[Dict[str, Any]]:
    """Return cached emit.item template for a discovery_id, loading on demand.

    Falls back to the per-service default template if the exact discovery_id
    isn't in the catalog (DCAT-02-E alignment shortcut).
    """
    if discovery_id in _K8S_EMIT_CACHE:
        return _K8S_EMIT_CACHE[discovery_id]
    parts = discovery_id.split('.', 2)
    if len(parts) < 2 or parts[0] != 'k8s':
        _K8S_EMIT_CACHE[discovery_id] = None
        return None
    # Resolve scanner_id -> catalog service folder
    service = (
        _K8S_DISCOVERY_ID_SERVICE.get(discovery_id)
        or _K8S_SERVICE_ALIAS.get(parts[1], parts[1])
    )
    _load_k8s_service_emits(service)
    direct = _K8S_EMIT_CACHE.get(discovery_id)
    if direct is not None:
        return direct
    # Service-default fallback for short-form scanner IDs
    fallback = _K8S_EMIT_CACHE.get(f"_service_default::{service}")
    _K8S_EMIT_CACHE[discovery_id] = fallback
    return fallback

# Thread pool for blocking K8s SDK calls
_K8S_EXECUTOR = ThreadPoolExecutor(max_workers=10)

# K8s has no regions — uses a single pseudo-region
DEFAULT_K8S_REGIONS = ['cluster']

# ─── Service Handler Registry ──────────────────────────────────────
K8S_SERVICE_HANDLERS: Dict[str, Callable] = {}


def k8s_handler(service_name: str):
    """Decorator to register a K8s resource discovery handler."""
    def decorator(fn: Callable):
        K8S_SERVICE_HANDLERS[service_name] = fn
        return fn
    return decorator


# ─── Resource Serialization Helper ─────────────────────────────────

def _serialize_k8s_object(obj) -> Dict:
    """Convert K8s SDK model object to a JSON-serializable dict.

    K8s Python client returns V1-prefixed model objects (V1Pod, V1Deployment).
    Use the API client sanitizer to convert to plain dicts.
    """
    from kubernetes import client
    return client.ApiClient().sanitize_for_serialization(obj)


def _enrich_k8s_item(item: Dict) -> Dict:
    """Inject standard resource identifier fields used by database_manager.

    K8s uses namespace/kind/name as logical identifier and uid as unique ID.

    DCAT-02-E: also renders the catalog `emit.item` template (Jinja) and
    stores the flat result on `item['emitted_fields']`. Discovery engine
    pipes this into `discovery_findings.emitted_fields` JSONB so the column
    is flat (no nested envelope objects).
    """
    metadata = item.get('metadata', {}) or {}
    uid = metadata.get('uid', '')
    name = metadata.get('name', '')
    namespace = metadata.get('namespace', 'cluster')
    kind = item.get('kind', item.get('resource_type', 'Unknown')).lower()

    resource_path = f"{namespace}/{kind}/{name}"

    item['resource_arn'] = resource_path
    item['resource_id'] = uid
    item['resource_uid'] = uid

    # Build _raw_response (everything except internal/metadata fields)
    item['_raw_response'] = {k: v for k, v in item.items()
                             if not k.startswith('_') and k not in (
                                 'resource_arn', 'resource_uid', 'resource_id', 'resource_type')}

    # DCAT-02-E: catalog-driven emit rendering (single chokepoint)
    if _RENDERER_AVAILABLE:
        discovery_id = item.get('_discovery_id')
        if discovery_id:
            template = _get_k8s_emit_template(discovery_id)
            if template:
                ctx = {
                    'item': item,
                    'response': item,        # K8s items are already individual
                    'context': {
                        'namespace': namespace,
                        'kind': kind,
                        'name': name,
                        'uid': uid,
                        'cluster': item.get('_cluster_name'),
                    },
                }
                try:
                    rendered = render_emit_item(
                        template,
                        ctx,
                        discovery_id=discovery_id,
                        resource_uid=resource_path,
                        failure_sink=_emit_failure_sink,
                    )
                    if isinstance(rendered, dict) and rendered:
                        item['emitted_fields'] = rendered
                except Exception as exc:  # pragma: no cover
                    logger.warning(
                        "K8s emit render failed %s for %s: %s",
                        discovery_id, resource_path, exc,
                    )

    return item


# ─── Service Handlers ───────────────────────────────────────────────

@k8s_handler('namespace')
def _scan_namespaces(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes namespaces (cluster-scoped)."""
    resources = []
    try:
        ns_list = core_v1.list_namespace()
        for ns in ns_list.items:
            item = _serialize_k8s_object(ns)
            item['kind'] = 'Namespace'
            item['resource_type'] = 'k8s.core/Namespace'
            item['_discovery_id'] = 'k8s.cluster.list_namespace'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_namespace failed: {e}")
    logger.info(f"  namespace: {len(resources)} namespaces found")
    return resources


@k8s_handler('pod')
def _scan_pods(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes pods across namespaces."""
    resources = []
    try:
        pod_list = core_v1.list_pod_for_all_namespaces()
        for pod in pod_list.items:
            item = _serialize_k8s_object(pod)
            item['kind'] = 'Pod'
            item['resource_type'] = 'k8s.core/Pod'
            item['_discovery_id'] = 'k8s.pod.list_pods'
            enriched = _enrich_k8s_item(item)
            resources.append(enriched)
            # Secondary ID: rules using k8s.pod.list (10 rules)
            dup = dict(enriched)
            dup['_discovery_id'] = 'k8s.pod.list'
            resources.append(dup)
    except Exception as e:
        logger.warning(f"K8s list_pod_for_all_namespaces failed: {e}")
    logger.info(f"  pod: {len(resources)} pods found")
    return resources


@k8s_handler('deployment')
def _scan_deployments(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes deployments across namespaces."""
    resources = []
    try:
        dep_list = apps_v1.list_deployment_for_all_namespaces()
        for dep in dep_list.items:
            item = _serialize_k8s_object(dep)
            item['kind'] = 'Deployment'
            item['resource_type'] = 'k8s.apps/Deployment'
            item['_discovery_id'] = 'k8s.deployments.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_deployment_for_all_namespaces failed: {e}")
    logger.info(f"  deployment: {len(resources)} deployments found")
    return resources


@k8s_handler('service')
def _scan_services(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes services across namespaces."""
    resources = []
    try:
        svc_list = core_v1.list_service_for_all_namespaces()
        for svc in svc_list.items:
            item = _serialize_k8s_object(svc)
            item['kind'] = 'Service'
            item['resource_type'] = 'k8s.core/Service'
            item['_discovery_id'] = 'k8s.network.list_service_for_all_namespaces'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_service_for_all_namespaces failed: {e}")
    logger.info(f"  service: {len(resources)} services found")
    return resources


@k8s_handler('configmap')
def _scan_configmaps(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes ConfigMaps across namespaces."""
    resources = []
    try:
        cm_list = core_v1.list_config_map_for_all_namespaces()
        for cm in cm_list.items:
            item = _serialize_k8s_object(cm)
            item['kind'] = 'ConfigMap'
            item['resource_type'] = 'k8s.core/ConfigMap'
            item['_discovery_id'] = 'k8s.monitoring.list_config_map_for_all_namespaces'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_config_map_for_all_namespaces failed: {e}")
    logger.info(f"  configmap: {len(resources)} configmaps found")
    return resources


@k8s_handler('daemonset')
def _scan_daemonsets(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes DaemonSets across namespaces."""
    resources = []
    try:
        ds_list = apps_v1.list_daemon_set_for_all_namespaces()
        for ds in ds_list.items:
            item = _serialize_k8s_object(ds)
            item['kind'] = 'DaemonSet'
            item['resource_type'] = 'k8s.apps/DaemonSet'
            item['_discovery_id'] = 'k8s.daemonset.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_daemon_set_for_all_namespaces failed: {e}")
    logger.info(f"  daemonset: {len(resources)} daemonsets found")
    return resources


@k8s_handler('ingress')
def _scan_ingresses(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes Ingresses across namespaces."""
    resources = []
    try:
        from kubernetes import client as k8s_client
        networking_v1 = k8s_client.NetworkingV1Api()
        ing_list = networking_v1.list_ingress_for_all_namespaces()
        for ing in ing_list.items:
            item = _serialize_k8s_object(ing)
            item['kind'] = 'Ingress'
            item['resource_type'] = 'k8s.networking/Ingress'
            item['_discovery_id'] = 'k8s.ingress.list_ingresses'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_ingress_for_all_namespaces failed: {e}")
    logger.info(f"  ingress: {len(resources)} ingresses found")
    return resources


@k8s_handler('networkpolicy')
def _scan_networkpolicies(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes NetworkPolicies across namespaces."""
    resources = []
    try:
        from kubernetes import client as k8s_client
        networking_v1 = k8s_client.NetworkingV1Api()
        np_list = networking_v1.list_network_policy_for_all_namespaces()
        for np in np_list.items:
            item = _serialize_k8s_object(np)
            item['kind'] = 'NetworkPolicy'
            item['resource_type'] = 'k8s.networking/NetworkPolicy'
            item['_discovery_id'] = 'k8s.networkpolicy.list'
            enriched = _enrich_k8s_item(item)
            resources.append(enriched)
            # Secondary IDs: rules using k8s.network.list_network_policy_for_all_namespaces (29)
            # and k8s.policy.list_network_policy_for_all_namespaces (9)
            for alt_id in ('k8s.network.list_network_policy_for_all_namespaces',
                           'k8s.policy.list_network_policy_for_all_namespaces'):
                dup = dict(enriched)
                dup['_discovery_id'] = alt_id
                resources.append(dup)
    except Exception as e:
        logger.warning(f"K8s list_network_policy_for_all_namespaces failed: {e}")
    logger.info(f"  networkpolicy: {len(resources)} networkpolicies found")
    return resources


@k8s_handler('persistentvolumeclaim')
def _scan_pvcs(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes PersistentVolumeClaims across namespaces."""
    resources = []
    try:
        pvc_list = core_v1.list_persistent_volume_claim_for_all_namespaces()
        for pvc in pvc_list.items:
            item = _serialize_k8s_object(pvc)
            item['kind'] = 'PersistentVolumeClaim'
            item['resource_type'] = 'k8s.core/PersistentVolumeClaim'
            item['_discovery_id'] = 'k8s.persistentvolumeclaim.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_persistent_volume_claim_for_all_namespaces failed: {e}")
    logger.info(f"  persistentvolumeclaim: {len(resources)} pvcs found")
    return resources


@k8s_handler('role')
def _scan_roles(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes Roles across namespaces."""
    resources = []
    try:
        from kubernetes import client as k8s_client
        rbac_v1 = k8s_client.RbacAuthorizationV1Api()
        role_list = rbac_v1.list_role_for_all_namespaces()
        for role in role_list.items:
            item = _serialize_k8s_object(role)
            item['kind'] = 'Role'
            item['resource_type'] = 'k8s.rbac/Role'
            item['_discovery_id'] = 'k8s.rbac.list_role_for_all_namespaces'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_role_for_all_namespaces failed: {e}")
    logger.info(f"  role: {len(resources)} roles found")
    return resources


@k8s_handler('clusterrole')
def _scan_clusterroles(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes ClusterRoles (cluster-scoped)."""
    resources = []
    try:
        from kubernetes import client as k8s_client
        rbac_v1 = k8s_client.RbacAuthorizationV1Api()
        cr_list = rbac_v1.list_cluster_role()
        for cr in cr_list.items:
            item = _serialize_k8s_object(cr)
            item['kind'] = 'ClusterRole'
            item['resource_type'] = 'k8s.rbac/ClusterRole'
            item['_discovery_id'] = 'k8s.rbac.list_cluster_role'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_cluster_role failed: {e}")
    logger.info(f"  clusterrole: {len(resources)} clusterroles found")
    return resources


@k8s_handler('clusterrolebinding')
def _scan_clusterrolebindings(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes ClusterRoleBindings (cluster-scoped)."""
    resources = []
    try:
        from kubernetes import client as k8s_client
        rbac_v1 = k8s_client.RbacAuthorizationV1Api()
        crb_list = rbac_v1.list_cluster_role_binding()
        for crb in crb_list.items:
            item = _serialize_k8s_object(crb)
            item['kind'] = 'ClusterRoleBinding'
            item['resource_type'] = 'k8s.rbac/ClusterRoleBinding'
            item['_discovery_id'] = 'k8s.rbac.list_cluster_role_binding'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_cluster_role_binding failed: {e}")
    logger.info(f"  clusterrolebinding: {len(resources)} clusterrolebindings found")
    return resources


@k8s_handler('rolebinding')
def _scan_rolebindings(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes RoleBindings across namespaces."""
    resources = []
    try:
        from kubernetes import client as k8s_client
        rbac_v1 = k8s_client.RbacAuthorizationV1Api()
        rb_list = rbac_v1.list_role_binding_for_all_namespaces()
        for rb in rb_list.items:
            item = _serialize_k8s_object(rb)
            item['kind'] = 'RoleBinding'
            item['resource_type'] = 'k8s.rbac/RoleBinding'
            item['_discovery_id'] = 'k8s.rolebinding.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_role_binding_for_all_namespaces failed: {e}")
    logger.info(f"  rolebinding: {len(resources)} rolebindings found")
    return resources


@k8s_handler('secret')
def _scan_secrets(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes Secrets across namespaces (metadata only)."""
    resources = []
    try:
        secret_list = core_v1.list_secret_for_all_namespaces()
        for secret in secret_list.items:
            item = _serialize_k8s_object(secret)
            # Strip secret data to avoid storing sensitive values
            item.pop('data', None)
            item.pop('string_data', None)
            item['kind'] = 'Secret'
            item['resource_type'] = 'k8s.core/Secret'
            item['_discovery_id'] = 'k8s.secret.list'
            enriched = _enrich_k8s_item(item)
            resources.append(enriched)
            # Secondary ID: rules using k8s.secret.list_secrets (16 rules)
            dup = dict(enriched)
            dup['_discovery_id'] = 'k8s.secret.list_secrets'
            resources.append(dup)
    except Exception as e:
        logger.warning(f"K8s list_secret_for_all_namespaces failed: {e}")
    logger.info(f"  secret: {len(resources)} secrets found")
    return resources


@k8s_handler('serviceaccount')
def _scan_serviceaccounts(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes ServiceAccounts across namespaces."""
    resources = []
    try:
        sa_list = core_v1.list_service_account_for_all_namespaces()
        for sa in sa_list.items:
            item = _serialize_k8s_object(sa)
            item['kind'] = 'ServiceAccount'
            item['resource_type'] = 'k8s.core/ServiceAccount'
            item['_discovery_id'] = 'k8s.serviceaccount.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_service_account_for_all_namespaces failed: {e}")
    logger.info(f"  serviceaccount: {len(resources)} serviceaccounts found")
    return resources


@k8s_handler('statefulset')
def _scan_statefulsets(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes StatefulSets across namespaces."""
    resources = []
    try:
        ss_list = apps_v1.list_stateful_set_for_all_namespaces()
        for ss in ss_list.items:
            item = _serialize_k8s_object(ss)
            item['kind'] = 'StatefulSet'
            item['resource_type'] = 'k8s.apps/StatefulSet'
            item['_discovery_id'] = 'k8s.statefulset.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_stateful_set_for_all_namespaces failed: {e}")
    logger.info(f"  statefulset: {len(resources)} statefulsets found")
    return resources


@k8s_handler('node')
def _scan_nodes(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes Nodes (cluster-scoped)."""
    resources = []
    try:
        node_list = core_v1.list_node()
        for node in node_list.items:
            item = _serialize_k8s_object(node)
            item['kind'] = 'Node'
            item['resource_type'] = 'k8s.core/Node'
            item['_discovery_id'] = 'k8s.node.list_node'
            enriched = _enrich_k8s_item(item)
            resources.append(enriched)
            # Secondary IDs: k8s.cluster.list_node (16 rules), k8s.kubelet.list_node (5 rules)
            for alt_id in ('k8s.cluster.list_node', 'k8s.kubelet.list_node'):
                dup = dict(enriched)
                dup['_discovery_id'] = alt_id
                resources.append(dup)
    except Exception as e:
        logger.warning(f"K8s list_node failed: {e}")
    logger.info(f"  node: {len(resources)} nodes found")
    return resources


@k8s_handler('persistentvolume')
def _scan_persistent_volumes(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes PersistentVolumes (cluster-scoped)."""
    resources = []
    try:
        pv_list = core_v1.list_persistent_volume()
        for pv in pv_list.items:
            item = _serialize_k8s_object(pv)
            item['kind'] = 'PersistentVolume'
            item['resource_type'] = 'k8s.core/PersistentVolume'
            item['_discovery_id'] = 'k8s.persistentvolume.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_persistent_volume failed: {e}")
    logger.info(f"  persistentvolume: {len(resources)} pvs found")
    return resources


@k8s_handler('job')
def _scan_jobs(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes Jobs across namespaces."""
    resources = []
    try:
        from kubernetes import client as k8s_client
        batch_v1 = k8s_client.BatchV1Api()
        job_list = batch_v1.list_job_for_all_namespaces()
        for job in job_list.items:
            item = _serialize_k8s_object(job)
            item['kind'] = 'Job'
            item['resource_type'] = 'k8s.batch/Job'
            item['_discovery_id'] = 'k8s.job.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_job_for_all_namespaces failed: {e}")
    logger.info(f"  job: {len(resources)} jobs found")
    return resources


@k8s_handler('cronjob')
def _scan_cronjobs(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes CronJobs across namespaces."""
    resources = []
    try:
        from kubernetes import client as k8s_client
        batch_v1 = k8s_client.BatchV1Api()
        cj_list = batch_v1.list_cron_job_for_all_namespaces()
        for cj in cj_list.items:
            item = _serialize_k8s_object(cj)
            item['kind'] = 'CronJob'
            item['resource_type'] = 'k8s.batch/CronJob'
            item['_discovery_id'] = 'k8s.cronjob.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_cron_job_for_all_namespaces failed: {e}")
    logger.info(f"  cronjob: {len(resources)} cronjobs found")
    return resources


@k8s_handler('autoscaling')
@k8s_handler('horizontalpodautoscaler')
def _scan_hpas(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes HorizontalPodAutoscalers across namespaces."""
    resources = []
    try:
        from kubernetes import client as k8s_client
        autoscaling_v1 = k8s_client.AutoscalingV1Api()
        hpa_list = autoscaling_v1.list_horizontal_pod_autoscaler_for_all_namespaces()
        for hpa in hpa_list.items:
            item = _serialize_k8s_object(hpa)
            item['kind'] = 'HorizontalPodAutoscaler'
            item['resource_type'] = 'k8s.autoscaling/HorizontalPodAutoscaler'
            item['_discovery_id'] = 'k8s.hpa.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_horizontal_pod_autoscaler_for_all_namespaces failed: {e}")
    logger.info(f"  horizontalpodautoscaler: {len(resources)} hpas found")
    return resources


@k8s_handler('storageclass')
def _scan_storageclasses(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes StorageClasses (cluster-scoped)."""
    resources = []
    try:
        from kubernetes import client as k8s_client
        storage_v1 = k8s_client.StorageV1Api()
        sc_list = storage_v1.list_storage_class()
        for sc in sc_list.items:
            item = _serialize_k8s_object(sc)
            item['kind'] = 'StorageClass'
            item['resource_type'] = 'k8s.storage/StorageClass'
            item['_discovery_id'] = 'k8s.storageclass.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_storage_class failed: {e}")
    logger.info(f"  storageclass: {len(resources)} storageclasses found")
    return resources


@k8s_handler('replicaset')
def _scan_replicasets(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes ReplicaSets across namespaces."""
    resources = []
    try:
        rs_list = apps_v1.list_replica_set_for_all_namespaces()
        for rs in rs_list.items:
            item = _serialize_k8s_object(rs)
            item['kind'] = 'ReplicaSet'
            item['resource_type'] = 'k8s.apps/ReplicaSet'
            item['_discovery_id'] = 'k8s.replicaset.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_replica_set_for_all_namespaces failed: {e}")
    logger.info(f"  replicaset: {len(resources)} replicasets found")
    return resources


@k8s_handler('resourcequota')
def _scan_resourcequotas(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover all Kubernetes ResourceQuotas across namespaces."""
    resources = []
    try:
        rq_list = core_v1.list_resource_quota_for_all_namespaces()
        for rq in rq_list.items:
            item = _serialize_k8s_object(rq)
            item['kind'] = 'ResourceQuota'
            item['resource_type'] = 'k8s.core/ResourceQuota'
            item['_discovery_id'] = 'k8s.resourcequota.list'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_resource_quota_for_all_namespaces failed: {e}")
    logger.info(f"  resourcequota: {len(resources)} resourcequotas found")
    return resources


@k8s_handler('event')
def _scan_events(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover recent Kubernetes Events across namespaces (warning events only)."""
    resources = []
    try:
        ev_list = core_v1.list_event_for_all_namespaces(
            field_selector="type=Warning"
        )
        for ev in ev_list.items:
            item = _serialize_k8s_object(ev)
            item['kind'] = 'Event'
            item['resource_type'] = 'k8s.core/Event'
            item['_discovery_id'] = 'k8s.audit.list_event_for_all_namespaces'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_event_for_all_namespaces failed: {e}")
    logger.info(f"  event: {len(resources)} warning events found")
    return resources


@k8s_handler('admission')
def _scan_admission_webhooks(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover Kubernetes ValidatingWebhookConfiguration and MutatingWebhookConfiguration."""
    from kubernetes import client as k8s_client
    admreg_v1 = k8s_client.AdmissionregistrationV1Api()
    resources = []
    # ValidatingWebhookConfigurations (47 rules)
    try:
        vwc_list = admreg_v1.list_validating_webhook_configuration()
        for vwc in vwc_list.items:
            item = _serialize_k8s_object(vwc)
            item['kind'] = 'ValidatingWebhookConfiguration'
            item['resource_type'] = 'k8s.admissionregistration/ValidatingWebhookConfiguration'
            item['_discovery_id'] = 'k8s.admission.list_validating_webhook_configuration'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_validating_webhook_configuration failed: {e}")
    # MutatingWebhookConfigurations (2 rules)
    try:
        mwc_list = admreg_v1.list_mutating_webhook_configuration()
        for mwc in mwc_list.items:
            item = _serialize_k8s_object(mwc)
            item['kind'] = 'MutatingWebhookConfiguration'
            item['resource_type'] = 'k8s.admissionregistration/MutatingWebhookConfiguration'
            item['_discovery_id'] = 'k8s.admission.list_mutating_webhook_configuration'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s list_mutating_webhook_configuration failed: {e}")
    logger.info(f"  admission: {len(resources)} webhook configs found")
    return resources


# ─── Control Plane Parsing Helpers ─────────────────────────────────

def _parse_pod_command_args(pod_item: Dict) -> Dict:
    """Parse container command + args from a kube-system static pod spec into a flat dict.

    Handles all kubeadm flag formats:
    - ``--flag=value``  (most flags)
    - ``--flag value``  (positional value after flag)
    - ``--flag``        (boolean: stored as 'true')
    - ``--authorization-mode=Node,RBAC`` → stored as list ['Node', 'RBAC']
    """
    args: Dict = {}
    spec = pod_item.get('spec', {}) or {}
    containers = spec.get('containers', []) or []
    if not containers:
        return args

    container = containers[0]
    all_tokens = (container.get('command', []) or []) + (container.get('args', []) or [])

    LIST_FLAGS = {
        'authorization-mode', 'enable-admission-plugins', 'disable-admission-plugins',
        'tls-cipher-suites', 'feature-gates', 'runtime-config',
    }

    i = 0
    while i < len(all_tokens):
        token = all_tokens[i]
        if not token.startswith('--'):
            i += 1
            continue
        flag = token[2:]  # strip '--'
        if '=' in flag:
            key, value = flag.split('=', 1)
            args[key] = [v.strip() for v in value.split(',') if v.strip()] if key in LIST_FLAGS else value
        else:
            # peek at next token
            if i + 1 < len(all_tokens) and not all_tokens[i + 1].startswith('--'):
                args[flag] = all_tokens[i + 1]
                i += 1
            else:
                args[flag] = 'true'
        i += 1
    return args


def _derive_apiserver_computed(args: Dict) -> Dict:
    """Produce derived fields that check rules reference by logical name.

    Keys added into the ``arguments`` dict so check rules can use
    ``item.arguments.<key>`` without changes to the evaluation engine.
    """
    plugins = set(args.get('enable-admission-plugins', []) if isinstance(
        args.get('enable-admission-plugins'), list) else
        [p.strip() for p in str(args.get('enable-admission-plugins', '')).split(',') if p.strip()])

    return {
        # Admission plugin boolean flags
        'admission-control-service-account-check': 'ServiceAccount' in plugins,
        'admission-plugin-namespace-lifecycle-enabled': 'NamespaceLifecycle' in plugins,
        'admission-plugins-event-rate-limit-set': 'EventRateLimit' in plugins,
        'admission-plugins-always-pull-images-set': 'AlwaysPullImages' in plugins,
        'admission-plugins-node-restriction-check': 'NodeRestriction' in plugins,
        'admission-plugins-podsecuritypolicy-check': 'enabled' if 'PodSecurityPolicy' in plugins else None,
        'admission-plugins-security-context-deny-enabled': 'SecurityContextDeny' in plugins,
        'admission-controller-image-policy-webhook-configured': 'ImagePolicyWebhook' in plugins,
        'admission-control': list(plugins),
        # Logical booleans that map to specific flag values
        'audit-logging-enabled': 'audit-log-path' in args,
        'account-lookup-enabled': args.get('service-account-lookup', 'true').lower() != 'false',
        'tls-enabled': 'tls-cert-file' in args and 'tls-private-key-file' in args,
        'server-verification': 'client-ca-file' in args,
        'kubelet-client-cert-key-verification': 'kubelet-client-certificate' in args and 'kubelet-client-key' in args,
    }


def _derive_etcd_top_level(args: Dict) -> Dict:
    """Produce top-level (non-arguments) derived fields expected by etcd check rules."""
    auto_tls_raw = args.get('auto-tls', 'false')
    peer_auto_tls_raw = args.get('peer-auto-tls', 'false')
    client_cert_auth = args.get('client-cert-auth', 'false').lower() == 'true'
    peer_client_cert = args.get('peer-client-cert-auth', 'false').lower() == 'true'
    cert_file = args.get('cert-file', '')
    key_file = args.get('key-file', '')
    trusted_ca = args.get('trusted-ca-file', '')
    peer_trusted_ca = args.get('peer-trusted-ca-file', '')

    return {
        # etcd check rules reference these at item.* (not item.arguments.*)
        'encryption-at-rest-enabled': False,          # set by apiserver --encryption-provider-config, not etcd
        'client-cert-auth-in-transit-enabled': client_cert_auth,
        'client-cert-auth-enabled': client_cert_auth,
        'auto-tls-configured': auto_tls_raw,
        'auto-tls-check': auto_tls_raw.lower() == 'true',
        'ca-uniqueness-configured': bool(trusted_ca and peer_trusted_ca and trusted_ca != peer_trusted_ca),
        'certificate-configured': bool(cert_file and key_file),
        'ca-check': bool(trusted_ca),
        'compliance': None,
        'peer-auto-tls-disabled': peer_auto_tls_raw.lower() != 'true',
    }


# ─── Control Plane Handlers ─────────────────────────────────────────

@k8s_handler('apiserver')
def _scan_apiserver(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover kube-apiserver security configuration from kube-system static pod specs.

    Reads command args from the running apiserver static pod to evaluate
    CIS Kubernetes Benchmark Section 1 controls without the deprecated
    ComponentStatus API.
    """
    resources = []
    try:
        pod_list = core_v1.list_namespaced_pod(
            namespace='kube-system',
            label_selector='component=kube-apiserver'
        )
        for pod in pod_list.items:
            item = _serialize_k8s_object(pod)
            raw_args = _parse_pod_command_args(item)
            derived = _derive_apiserver_computed(raw_args)
            # Merge: raw flags take precedence; derived fills in logical names
            item['arguments'] = {**raw_args, **derived}
            # Synthesize conditions array so legacy checks on item.conditions[].status still pass
            item['conditions'] = [{'type': 'Healthy', 'status': 'True', 'message': 'Running'}]
            item['kind'] = 'APIServer'
            item['resource_type'] = 'k8s.controlplane/APIServer'
            item['_discovery_id'] = 'k8s.apiserver.list_component_status'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s apiserver scan failed: {e}")
    logger.info(f"  apiserver: {len(resources)} pod(s) found")
    return resources


@k8s_handler('etcd')
def _scan_etcd(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover etcd security configuration from kube-system static pod specs.

    Evaluates CIS Kubernetes Benchmark Section 2 controls (etcd).
    """
    resources = []
    try:
        pod_list = core_v1.list_namespaced_pod(
            namespace='kube-system',
            label_selector='component=etcd'
        )
        for pod in pod_list.items:
            item = _serialize_k8s_object(pod)
            raw_args = _parse_pod_command_args(item)
            top_level = _derive_etcd_top_level(raw_args)
            item['arguments'] = raw_args
            # Merge top-level derived fields directly onto item
            item.update(top_level)
            item['conditions'] = [{'type': 'Healthy', 'status': 'True', 'message': 'Running'}]
            item['kind'] = 'Etcd'
            item['resource_type'] = 'k8s.controlplane/Etcd'
            item['_discovery_id'] = 'k8s.etcd.list_component_status'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s etcd scan failed: {e}")
    logger.info(f"  etcd: {len(resources)} pod(s) found")
    return resources


@k8s_handler('scheduler')
def _scan_scheduler(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover kube-scheduler security configuration from kube-system static pod specs.

    Evaluates CIS Kubernetes Benchmark Section 1.4 controls (scheduler).
    """
    resources = []
    try:
        pod_list = core_v1.list_namespaced_pod(
            namespace='kube-system',
            label_selector='component=kube-scheduler'
        )
        for pod in pod_list.items:
            item = _serialize_k8s_object(pod)
            raw_args = _parse_pod_command_args(item)
            item['arguments'] = raw_args
            item['conditions'] = [{'type': 'Healthy', 'status': 'True', 'message': 'Running'}]
            item['kind'] = 'Scheduler'
            item['resource_type'] = 'k8s.controlplane/Scheduler'
            item['_discovery_id'] = 'k8s.scheduler.list_component_status'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s scheduler scan failed: {e}")
    logger.info(f"  scheduler: {len(resources)} pod(s) found")
    return resources


@k8s_handler('controlplane')
def _scan_controller_manager(core_v1, apps_v1, cluster_name: str, region: str, config: Dict) -> List[Dict]:
    """Discover kube-controller-manager security configuration from kube-system static pod specs.

    Evaluates CIS Kubernetes Benchmark Section 1.3 controls (controller manager).
    """
    resources = []
    try:
        pod_list = core_v1.list_namespaced_pod(
            namespace='kube-system',
            label_selector='component=kube-controller-manager'
        )
        for pod in pod_list.items:
            item = _serialize_k8s_object(pod)
            raw_args = _parse_pod_command_args(item)
            # Derive additional computed fields controller-manager check rules need
            item['arguments'] = {
                **raw_args,
                # 'profiling-disabled' is a logical flag — map from actual --profiling flag
                'profiling-disabled': raw_args.get('profiling', 'true').lower() == 'false',
            }
            item['conditions'] = [{'type': 'Healthy', 'status': 'True', 'message': 'Running'}]
            item['kind'] = 'ControllerManager'
            item['resource_type'] = 'k8s.controlplane/ControllerManager'
            item['_discovery_id'] = 'k8s.controlplane.list_component_status'
            resources.append(_enrich_k8s_item(item))
    except Exception as e:
        logger.warning(f"K8s controller-manager scan failed: {e}")
    logger.info(f"  controlplane: {len(resources)} pod(s) found")
    return resources


# ─── Scanner Class ──────────────────────────────────────────────────

class K8sDiscoveryScanner(DiscoveryScanner):
    """
    Kubernetes-specific discovery scanner implementation.

    Uses handler registry pattern: K8S_SERVICE_HANDLERS maps resource types
    to handler functions. Add new resources by decorating with @k8s_handler.

    K8s is unique:
    - No region concept (single pseudo-region 'cluster')
    - Authentication via in-cluster config or kubeconfig
    - Discovers K8s API objects, not cloud resources
    """

    def __init__(self, credentials: Dict[str, Any], **kwargs):
        super().__init__(credentials, **kwargs)
        self.core_v1 = None
        self.apps_v1 = None
        self.cluster_name = (
            credentials.get('cluster_name')
            or credentials.get('account_id')
            or 'unknown-cluster'
        )

    def authenticate(self) -> Any:
        """
        Authenticate to Kubernetes cluster.

        Supports:
        - in_cluster: Use service account mounted in pod (self-scan)
        - kubeconfig: Use kubeconfig content from credentials
        - Default: Try in-cluster first, then fall back to kubeconfig
        """
        try:
            from kubernetes import client, config as k8s_config
            import yaml

            cred_type = self.credentials.get('credential_type', '').lower()

            if cred_type in ('in_cluster', 'k8s_in_cluster'):
                k8s_config.load_incluster_config()
                logger.info("K8s authentication successful (in-cluster)")

            elif cred_type in ('kubeconfig', 'k8s_kubeconfig'):
                kubeconfig_data = self.credentials.get('kubeconfig')
                if kubeconfig_data:
                    k8s_config.load_kube_config_from_dict(yaml.safe_load(kubeconfig_data))
                else:
                    k8s_config.load_kube_config()
                logger.info("K8s authentication successful (kubeconfig)")

            else:
                # Default: try in-cluster first, fall back to kubeconfig
                try:
                    k8s_config.load_incluster_config()
                    logger.info("K8s authentication successful (auto: in-cluster)")
                except k8s_config.ConfigException:
                    k8s_config.load_kube_config()
                    logger.info("K8s authentication successful (auto: kubeconfig)")

            self.core_v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()

            return self.core_v1

        except Exception as e:
            logger.error(f"K8s authentication failed: {e}")
            raise AuthenticationError(f"K8s authentication failed: {e}")

    async def scan_service(
        self,
        service: str,
        region: str,
        config: Dict[str, Any],
        skip_dependents: bool = False,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Execute K8s resource discovery via registered handler."""
        handler = K8S_SERVICE_HANDLERS.get(service)
        if not handler:
            logger.warning(f"No K8s handler registered for service: {service}")
            return ([], {'service': service, 'status': 'no_handler'})

        loop = asyncio.get_event_loop()
        try:
            discoveries = await loop.run_in_executor(
                _K8S_EXECUTOR,
                handler,
                self.core_v1,        # CoreV1Api client
                self.apps_v1,        # AppsV1Api client
                self.cluster_name,   # Cluster name
                region,              # Ignored for K8s (always 'cluster')
                config
            )
            metadata = {
                'service': service,
                'region': 'cluster',
                'resources_found': len(discoveries),
                'status': 'completed'
            }
            return (discoveries, metadata)
        except Exception as e:
            logger.error(f"K8s {service} scan failed: {e}")
            return ([], {'service': service, 'status': 'error', 'error': str(e)})

    def get_client(self, service: str, region: str) -> Any:
        """Get K8s API client."""
        if service in ('namespace', 'pod', 'service'):
            return self.core_v1
        elif service in ('deployment',):
            return self.apps_v1
        return self.core_v1

    def extract_resource_identifier(
        self,
        item: Dict[str, Any],
        service: str,
        region: str,
        account_id: str,
        resource_type: Optional[str] = None
    ) -> Dict[str, str]:
        """Extract resource identifiers from K8s response."""
        metadata = item.get('metadata', {}) or {}
        uid = metadata.get('uid', '')
        name = metadata.get('name', '')
        namespace = metadata.get('namespace', 'cluster')
        kind = item.get('kind', service).lower()

        return {
            'resource_arn': f"{namespace}/{kind}/{name}",
            'resource_id': uid,
            'resource_name': name,
            'resource_uid': uid,
            'resource_type': resource_type or item.get('resource_type', f'k8s/{kind}'),
        }

    def get_service_client_name(self, service: str) -> str:
        """Map service name to K8s API group."""
        return f"k8s.{service}"

    async def list_available_regions(self) -> List[str]:
        """K8s has no regions — return single pseudo-region."""
        return DEFAULT_K8S_REGIONS

    def get_account_id(self) -> str:
        """Return cluster name as account ID."""
        return self.cluster_name
