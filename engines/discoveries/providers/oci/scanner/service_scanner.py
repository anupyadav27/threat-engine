"""
OCI Discovery Scanner

Implements OCI-specific discovery using handler registry pattern.
Each service handler is a simple function registered via @oci_handler decorator.
"""

from typing import Dict, List, Any, Optional, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor
import asyncio
import logging

from common.models.provider_interface import DiscoveryScanner, AuthenticationError, DiscoveryError

logger = logging.getLogger(__name__)

# Thread pool for blocking OCI SDK calls
_OCI_EXECUTOR = ThreadPoolExecutor(max_workers=10)

DEFAULT_OCI_REGIONS = [
    'us-ashburn-1', 'us-phoenix-1', 'us-sanjose-1',
    'eu-frankfurt-1', 'eu-amsterdam-1', 'eu-zurich-1',
    'uk-london-1', 'ap-mumbai-1', 'ap-tokyo-1',
    'ap-sydney-1', 'ca-toronto-1', 'sa-saopaulo-1',
]

# ─── Service Handler Registry ──────────────────────────────────────
OCI_SERVICE_HANDLERS: Dict[str, Callable] = {}


def oci_handler(service_name: str):
    """Decorator to register an OCI service discovery handler."""
    def decorator(fn: Callable):
        OCI_SERVICE_HANDLERS[service_name] = fn
        return fn
    return decorator


# ─── Resource Identifier Helper ────────────────────────────────────

def _enrich_oci_item(item: Dict) -> Dict:
    """Inject standard resource identifier fields used by database_manager.

    OCI resources use OCID as primary identifier. This maps them to
    resource_arn/resource_uid/resource_id so the DB layer stores them.
    """
    ocid = item.get('id', '')
    item['resource_arn'] = ocid       # OCID as ARN equivalent
    item['resource_id'] = ocid
    item['resource_uid'] = ocid

    # Build _raw_response (everything except internal/metadata fields)
    item['_raw_response'] = {k: v for k, v in item.items()
                             if not k.startswith('_') and k not in (
                                 'resource_arn', 'resource_uid', 'resource_id', 'resource_type')}
    return item


# ─── Service Handlers ───────────────────────────────────────────────

@oci_handler('audit')
def _scan_audit(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI audit events (tenancy-scoped, last 24h)."""
    import oci
    from datetime import datetime, timedelta, timezone

    audit_client = oci.audit.AuditClient(config_dict, signer=signer)

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)

    resources = []
    try:
        response = oci.pagination.list_call_get_all_results(
            audit_client.list_events,
            compartment_id=tenancy_id,
            start_time=start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            end_time=end_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        )
        for event in response.data:
            item = {
                'id': getattr(event, 'event_id', ''),
                'event_type': getattr(event, 'event_type', ''),
                'source': getattr(event, 'source', ''),
                'compartment_id': getattr(event, 'compartment_id', ''),
                'event_time': str(getattr(event, 'event_time', '')),
                'credential_id': getattr(event, 'credential_id', ''),
                'request_action': getattr(event, 'request_action', ''),
                'request_agent': getattr(event, 'request_agent', ''),
                'resource_type': 'oci.audit/Event',
                '_discovery_id': 'oci.audit.list_events',
            }
            resources.append(_enrich_oci_item(item))
    except oci.exceptions.ServiceError as e:
        logger.warning(f"OCI audit list_events failed: {e.message}")
    except Exception as e:
        logger.warning(f"OCI audit scan error: {e}")

    # Audit configuration (separate from events)
    try:
        cfg = audit_client.get_configuration(compartment_id=tenancy_id).data
        item = {
            'id': f"{tenancy_id}/audit_configuration",
            'compartment_id': tenancy_id,
            'retention_period_days': getattr(cfg, 'retention_period_days', 0),
            'resource_type': 'oci.audit/Configuration',
            '_discovery_id': 'oci.audit.get_configuration',
        }
        resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.debug(f"OCI audit get_configuration failed: {e}")

    logger.info(f"  audit/{region}: {len(resources)} audit resources found")
    return resources


@oci_handler('compute')
def _scan_compute(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI compute instances in a compartment."""
    import oci

    compute_client = oci.core.ComputeClient(config_dict, signer=signer)

    resources = []
    try:
        response = oci.pagination.list_call_get_all_results(
            compute_client.list_instances,
            compartment_id=tenancy_id,
        )
        for instance in response.data:
            item = {
                'id': instance.id,
                'display_name': instance.display_name,
                'lifecycle_state': instance.lifecycle_state,
                'availability_domain': instance.availability_domain,
                'shape': instance.shape,
                'region': instance.region,
                'compartment_id': instance.compartment_id,
                'time_created': str(instance.time_created),
                'image_id': getattr(instance, 'image_id', None),
                'fault_domain': getattr(instance, 'fault_domain', None),
                'freeform_tags': instance.freeform_tags or {},
                'defined_tags': instance.defined_tags or {},
                'resource_type': 'oci.core/Instance',
                '_discovery_id': 'oci.compute.list_instances',
            }
            resources.append(_enrich_oci_item(item))
    except oci.exceptions.ServiceError as e:
        logger.warning(f"OCI compute list_instances failed: {e.message}")
    except Exception as e:
        logger.warning(f"OCI compute scan error: {e}")
    logger.info(f"  compute/{region}: {len(resources)} instances found")
    return resources


@oci_handler('database')
def _scan_database(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI database systems in a compartment."""
    import oci

    db_client = oci.database.DatabaseClient(config_dict, signer=signer)

    resources = []
    try:
        response = oci.pagination.list_call_get_all_results(
            db_client.list_db_systems,
            compartment_id=tenancy_id,
        )
        for db_system in response.data:
            item = {
                'id': db_system.id,
                'display_name': db_system.display_name,
                'lifecycle_state': db_system.lifecycle_state,
                'availability_domain': db_system.availability_domain,
                'shape': db_system.shape,
                'compartment_id': db_system.compartment_id,
                'database_edition': getattr(db_system, 'database_edition', None),
                'time_created': str(db_system.time_created),
                'hostname': getattr(db_system, 'hostname', None),
                'domain': getattr(db_system, 'domain', None),
                'cpu_core_count': getattr(db_system, 'cpu_core_count', None),
                'data_storage_size_in_gbs': getattr(db_system, 'data_storage_size_in_gbs', None),
                'freeform_tags': db_system.freeform_tags or {},
                'defined_tags': db_system.defined_tags or {},
                'resource_type': 'oci.database/DbSystem',
                '_discovery_id': 'oci.database.list_db_systems',
            }
            resources.append(_enrich_oci_item(item))
    except oci.exceptions.ServiceError as e:
        logger.warning(f"OCI database list_db_systems failed: {e.message}")
    except Exception as e:
        logger.warning(f"OCI database scan error: {e}")

    # Autonomous databases
    try:
        resp = oci.pagination.list_call_get_all_results(
            db_client.list_autonomous_databases, compartment_id=tenancy_id)
        for adb in resp.data:
            item = {
                'id': adb.id, 'display_name': adb.display_name,
                'lifecycle_state': adb.lifecycle_state,
                'db_workload': getattr(adb, 'db_workload', ''),
                'is_auto_scaling_enabled': getattr(adb, 'is_auto_scaling_enabled', False),
                'is_free_tier': getattr(adb, 'is_free_tier', False),
                'data_storage_size_in_tbs': getattr(adb, 'data_storage_size_in_tbs', 0),
                'cpu_core_count': getattr(adb, 'cpu_core_count', 0),
                'freeform_tags': adb.freeform_tags or {},
                'resource_type': 'oci.database/AutonomousDatabase',
                '_discovery_id': 'oci.database.list_autonomous_databases',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI database list_autonomous_databases failed: {e}")

    logger.info(f"  database/{region}: {len(resources)} database resources found")
    return resources


@oci_handler('object_storage')
def _scan_object_storage(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI Object Storage buckets."""
    import oci

    os_client = oci.object_storage.ObjectStorageClient(config_dict, signer=signer)

    resources = []
    try:
        # Get namespace first (required for bucket listing)
        namespace = os_client.get_namespace(compartment_id=tenancy_id).data

        response = oci.pagination.list_call_get_all_results(
            os_client.list_buckets,
            namespace_name=namespace,
            compartment_id=tenancy_id,
        )
        for bucket in response.data:
            item = {
                'id': f"oci.objectstorage:{namespace}:{bucket.name}",
                'name': bucket.name,
                'namespace': namespace,
                'compartment_id': bucket.compartment_id,
                'time_created': str(bucket.time_created),
                'etag': getattr(bucket, 'etag', None),
                'freeform_tags': bucket.freeform_tags or {},
                'defined_tags': bucket.defined_tags or {},
                'resource_type': 'oci.objectstorage/Bucket',
                '_discovery_id': 'oci.object_storage.list_buckets',
            }
            resources.append(_enrich_oci_item(item))

            # Pre-authenticated requests per bucket
            try:
                par_resp = oci.pagination.list_call_get_all_results(
                    os_client.list_preauthenticated_requests,
                    namespace_name=namespace,
                    bucket_name=bucket.name)
                for par in par_resp.data:
                    par_item = {
                        'id': par.id, 'name': par.name,
                        'bucket_name': bucket.name, 'namespace': namespace,
                        'access_type': getattr(par, 'access_type', ''),
                        'time_expires': str(getattr(par, 'time_expires', '')),
                        'time_created': str(getattr(par, 'time_created', '')),
                        'resource_type': 'oci.objectstorage/PreauthenticatedRequest',
                        '_discovery_id': 'oci.object_storage.list_preauthenticated_requests',
                    }
                    resources.append(_enrich_oci_item(par_item))
            except Exception:
                pass
    except oci.exceptions.ServiceError as e:
        logger.warning(f"OCI object_storage failed: {e.message}")
    except Exception as e:
        logger.warning(f"OCI object_storage scan error: {e}")
    logger.info(f"  object_storage/{region}: {len(resources)} buckets found")
    return resources


@oci_handler('identity')
def _scan_identity(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI IAM: users, policies, dynamic groups, auth policy, group memberships."""
    import oci
    if region and region not in ('us-ashburn-1', 'us-phoenix-1', 'global', ''):
        return []  # IAM is global — scan once from home region

    identity_client = oci.identity.IdentityClient(config_dict, signer=signer)
    resources = []

    # Users
    try:
        resp = oci.pagination.list_call_get_all_results(identity_client.list_users, compartment_id=tenancy_id)
        for user in resp.data:
            base = {
                'id': user.id, 'name': user.name, 'description': getattr(user, 'description', ''),
                'lifecycle_state': user.lifecycle_state,
                'time_created': str(user.time_created),
                'is_mfa_activated': getattr(user, 'is_mfa_activated', False),
                'can_use_console_password': getattr(user, 'can_use_console_password', False),
                'can_use_api_keys': getattr(user, 'can_use_api_keys', False),
                'can_use_auth_tokens': getattr(user, 'can_use_auth_tokens', False),
                'freeform_tags': user.freeform_tags or {},
                'resource_type': 'oci.identity/User',
                '_discovery_id': 'oci.identity.list_users',
            }
            resources.append(_enrich_oci_item(base))

            # Per-user: customer secret keys
            try:
                sk_resp = identity_client.list_customer_secret_keys(user_id=user.id)
                for sk in (sk_resp.data or []):
                    item = {
                        'id': getattr(sk, 'id', f"{user.id}/secret_key/{sk}"),
                        'user_id': user.id, 'user_name': user.name,
                        'display_name': getattr(sk, 'display_name', ''),
                        'lifecycle_state': getattr(sk, 'lifecycle_state', ''),
                        'time_created': str(getattr(sk, 'time_created', '')),
                        'resource_type': 'oci.identity/CustomerSecretKey',
                        '_discovery_id': 'oci.identity.list_customer_secret_keys',
                    }
                    resources.append(_enrich_oci_item(item))
            except Exception:
                pass

            # Per-user: swift passwords
            try:
                sw_resp = identity_client.list_swift_passwords(user_id=user.id)
                for sw in (sw_resp.data or []):
                    item = {
                        'id': getattr(sw, 'id', f"{user.id}/swift/{sw}"),
                        'user_id': user.id, 'user_name': user.name,
                        'description': getattr(sw, 'description', ''),
                        'lifecycle_state': getattr(sw, 'lifecycle_state', ''),
                        'resource_type': 'oci.identity/SwiftPassword',
                        '_discovery_id': 'oci.identity.list_swift_passwords',
                    }
                    resources.append(_enrich_oci_item(item))
            except Exception:
                pass

            # Per-user: UI password info
            try:
                pw = identity_client.get_user_ui_password_information(user_id=user.id).data
                item = {
                    'id': f"{user.id}/ui_password",
                    'user_id': user.id, 'user_name': user.name,
                    'time_password_created': str(getattr(pw, 'time_password_created', '')),
                    'lifecycle_state': getattr(pw, 'lifecycle_state', ''),
                    'resource_type': 'oci.identity/UserUiPassword',
                    '_discovery_id': 'oci.identity.get_user_ui_password_information',
                }
                resources.append(_enrich_oci_item(item))
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"OCI identity list_users failed: {e}")

    # Policies
    try:
        resp = oci.pagination.list_call_get_all_results(identity_client.list_policies, compartment_id=tenancy_id)
        for policy in resp.data:
            item = {
                'id': policy.id, 'name': policy.name,
                'statements': getattr(policy, 'statements', []),
                'lifecycle_state': policy.lifecycle_state,
                'time_created': str(policy.time_created),
                'freeform_tags': policy.freeform_tags or {},
                'resource_type': 'oci.identity/Policy',
                '_discovery_id': 'oci.identity.list_policies',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI identity list_policies failed: {e}")

    # Dynamic groups
    try:
        resp = oci.pagination.list_call_get_all_results(identity_client.list_dynamic_groups, compartment_id=tenancy_id)
        for dg in resp.data:
            item = {
                'id': dg.id, 'name': dg.name,
                'matching_rule': getattr(dg, 'matching_rule', ''),
                'lifecycle_state': dg.lifecycle_state,
                'resource_type': 'oci.identity/DynamicGroup',
                '_discovery_id': 'oci.identity.list_dynamic_groups',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI identity list_dynamic_groups failed: {e}")

    # User group memberships
    try:
        resp = oci.pagination.list_call_get_all_results(identity_client.list_user_group_memberships, compartment_id=tenancy_id)
        for m in resp.data:
            item = {
                'id': m.id, 'user_id': m.user_id, 'group_id': m.group_id,
                'lifecycle_state': m.lifecycle_state,
                'resource_type': 'oci.identity/UserGroupMembership',
                '_discovery_id': 'oci.identity.list_user_group_memberships',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI identity list_user_group_memberships failed: {e}")

    # Authentication policy
    try:
        auth_policy = identity_client.get_authentication_policy(compartment_id=tenancy_id).data
        item = {
            'id': f"{tenancy_id}/authentication_policy",
            'compartment_id': tenancy_id,
            'password_policy': {k: getattr(getattr(auth_policy, 'password_policy', None), k, None)
                                for k in ('minimum_password_length', 'is_uppercase_characters_required',
                                          'is_lowercase_characters_required', 'is_numeric_characters_required',
                                          'is_special_characters_required', 'is_username_containment_blocked')},
            'resource_type': 'oci.identity/AuthenticationPolicy',
            '_discovery_id': 'oci.identity.get_authentication_policy',
        }
        resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI identity get_authentication_policy failed: {e}")

    logger.info(f"  identity/{region}: {len(resources)} IAM resources found")
    return resources


@oci_handler('virtual_network')
def _scan_virtual_network(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI VCNs, subnets, security lists, route tables, internet gateways."""
    import oci
    vn_client = oci.core.VirtualNetworkClient(config_dict, signer=signer)
    resources = []

    # VCNs
    vcn_ids = []
    try:
        resp = oci.pagination.list_call_get_all_results(vn_client.list_vcns, compartment_id=tenancy_id)
        for vcn in resp.data:
            vcn_ids.append(vcn.id)
            item = {
                'id': vcn.id, 'display_name': vcn.display_name,
                'cidr_block': vcn.cidr_block, 'lifecycle_state': vcn.lifecycle_state,
                'freeform_tags': vcn.freeform_tags or {},
                'resource_type': 'oci.core/Vcn',
                '_discovery_id': 'oci.virtual_network.list_vcns',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI virtual_network list_vcns failed: {e}")

    # Security Lists
    try:
        resp = oci.pagination.list_call_get_all_results(vn_client.list_security_lists, compartment_id=tenancy_id)
        for sl in resp.data:
            item = {
                'id': sl.id, 'display_name': sl.display_name, 'vcn_id': sl.vcn_id,
                'lifecycle_state': sl.lifecycle_state,
                'ingress_security_rules': [str(r) for r in (sl.ingress_security_rules or [])],
                'egress_security_rules': [str(r) for r in (sl.egress_security_rules or [])],
                'resource_type': 'oci.core/SecurityList',
                '_discovery_id': 'oci.virtual_network.list_security_lists',
            }
            enriched = _enrich_oci_item(item)
            resources.append(enriched)
            dup = dict(enriched); dup['_discovery_id'] = 'oci.core.get_security_list'
            resources.append(dup)
    except Exception as e:
        logger.warning(f"OCI virtual_network list_security_lists failed: {e}")

    # Subnets
    try:
        resp = oci.pagination.list_call_get_all_results(vn_client.list_subnets, compartment_id=tenancy_id)
        for subnet in resp.data:
            item = {
                'id': subnet.id, 'display_name': subnet.display_name,
                'vcn_id': subnet.vcn_id, 'cidr_block': subnet.cidr_block,
                'lifecycle_state': subnet.lifecycle_state,
                'prohibit_public_ip_on_vnic': getattr(subnet, 'prohibit_public_ip_on_vnic', False),
                'resource_type': 'oci.core/Subnet',
                '_discovery_id': 'oci.virtual_network.list_subnets',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI virtual_network list_subnets failed: {e}")

    # Route Tables
    try:
        resp = oci.pagination.list_call_get_all_results(vn_client.list_route_tables, compartment_id=tenancy_id)
        for rt in resp.data:
            item = {
                'id': rt.id, 'display_name': rt.display_name, 'vcn_id': rt.vcn_id,
                'lifecycle_state': rt.lifecycle_state,
                'resource_type': 'oci.core/RouteTable',
                '_discovery_id': 'oci.virtual_network.list_route_tables',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI virtual_network list_route_tables failed: {e}")

    # Internet Gateways
    try:
        resp = oci.pagination.list_call_get_all_results(vn_client.list_internet_gateways, compartment_id=tenancy_id)
        for igw in resp.data:
            item = {
                'id': igw.id, 'display_name': igw.display_name, 'vcn_id': igw.vcn_id,
                'lifecycle_state': igw.lifecycle_state,
                'is_enabled': getattr(igw, 'is_enabled', True),
                'resource_type': 'oci.core/InternetGateway',
                '_discovery_id': 'oci.virtual_network.list_internet_gateways',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI virtual_network list_internet_gateways failed: {e}")

    # IPSec connections
    try:
        resp = oci.pagination.list_call_get_all_results(vn_client.list_ip_sec_connections, compartment_id=tenancy_id)
        for conn in resp.data:
            item = {
                'id': conn.id, 'display_name': conn.display_name,
                'lifecycle_state': conn.lifecycle_state,
                'resource_type': 'oci.core/IpSecConnection',
                '_discovery_id': 'oci.virtual_network.list_ip_sec_connections',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI virtual_network list_ip_sec_connections failed: {e}")

    # Network Security Groups + their rules
    try:
        resp = oci.pagination.list_call_get_all_results(vn_client.list_network_security_groups, compartment_id=tenancy_id)
        for nsg in resp.data:
            try:
                rules_resp = oci.pagination.list_call_get_all_results(
                    vn_client.list_network_security_group_security_rules,
                    network_security_group_id=nsg.id)
                rules = [{'direction': getattr(r, 'direction', ''),
                          'protocol': getattr(r, 'protocol', ''),
                          'source': getattr(r, 'source', ''),
                          'destination': getattr(r, 'destination', '')}
                         for r in (rules_resp.data or [])]
            except Exception:
                rules = []
            item = {
                'id': nsg.id, 'display_name': nsg.display_name, 'vcn_id': nsg.vcn_id,
                'lifecycle_state': nsg.lifecycle_state, 'security_rules': rules,
                'resource_type': 'oci.core/NetworkSecurityGroup',
                '_discovery_id': 'oci.core.list_network_security_group_security_rules',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI virtual_network list_network_security_groups failed: {e}")

    logger.info(f"  virtual_network/{region}: {len(resources)} networking resources found")
    return resources


@oci_handler('container_engine')
def _scan_container_engine(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI OKE clusters and node pools."""
    import oci
    ce_client = oci.container_engine.ContainerEngineClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(ce_client.list_clusters, compartment_id=tenancy_id)
        for cluster in resp.data:
            item = {
                'id': cluster.id, 'name': cluster.name,
                'lifecycle_state': cluster.lifecycle_state,
                'kubernetes_version': getattr(cluster, 'kubernetes_version', ''),
                'endpoint': getattr(getattr(cluster, 'endpoint_config', None), 'is_public_ip_enabled', None),
                'vcn_id': getattr(cluster, 'vcn_id', ''),
                'resource_type': 'oci.container_engine/Cluster',
                '_discovery_id': 'oci.container_engine.list_clusters',
            }
            enriched = _enrich_oci_item(item)
            resources.append(enriched)
            dup = dict(enriched); dup['_discovery_id'] = 'oci.oke.list_clusters'
            resources.append(dup)
    except Exception as e:
        logger.warning(f"OCI container_engine list_clusters failed: {e}")

    try:
        resp = oci.pagination.list_call_get_all_results(ce_client.list_node_pools, compartment_id=tenancy_id)
        for pool in resp.data:
            item = {
                'id': pool.id, 'name': pool.name, 'cluster_id': pool.cluster_id,
                'lifecycle_state': pool.lifecycle_state,
                'node_shape': getattr(pool, 'node_shape', ''),
                'kubernetes_version': getattr(pool, 'kubernetes_version', ''),
                'resource_type': 'oci.container_engine/NodePool',
                '_discovery_id': 'oci.container_engine.list_node_pools',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI container_engine list_node_pools failed: {e}")

    logger.info(f"  container_engine/{region}: {len(resources)} OKE resources found")
    return resources


@oci_handler('logging')
def _scan_logging(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI log groups and logs."""
    import oci
    log_client = oci.logging.LoggingManagementClient(config_dict, signer=signer)
    resources = []

    try:
        groups_resp = oci.pagination.list_call_get_all_results(log_client.list_log_groups, compartment_id=tenancy_id)
        for group in groups_resp.data:
            try:
                logs_resp = oci.pagination.list_call_get_all_results(
                    log_client.list_logs, log_group_id=group.id)
                for log in logs_resp.data:
                    item = {
                        'id': log.id, 'display_name': log.display_name,
                        'log_group_id': group.id, 'log_group_name': group.display_name,
                        'log_type': getattr(log, 'log_type', ''),
                        'lifecycle_state': log.lifecycle_state,
                        'is_enabled': getattr(log, 'is_enabled', False),
                        'resource_type': 'oci.logging/Log',
                        '_discovery_id': 'oci.logging.list_logs',
                    }
                    resources.append(_enrich_oci_item(item))
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"OCI logging list_log_groups failed: {e}")

    logger.info(f"  logging/{region}: {len(resources)} logs found")
    return resources


@oci_handler('key_management')
def _scan_key_management(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI KMS vaults and keys."""
    import oci
    kms_vaults_client = oci.key_management.KmsVaultClient(config_dict, signer=signer)
    resources = []

    try:
        vaults_resp = oci.pagination.list_call_get_all_results(kms_vaults_client.list_vaults, compartment_id=tenancy_id)
        for vault in vaults_resp.data:
            item = {
                'id': vault.id, 'display_name': vault.display_name,
                'lifecycle_state': vault.lifecycle_state,
                'vault_type': getattr(vault, 'vault_type', ''),
                'crypto_endpoint': getattr(vault, 'crypto_endpoint', ''),
                'management_endpoint': getattr(vault, 'management_endpoint', ''),
                'resource_type': 'oci.key_management/Vault',
                '_discovery_id': 'oci.key_management.list_vaults',
            }
            resources.append(_enrich_oci_item(item))

            # List keys within this vault
            mgmt_endpoint = getattr(vault, 'management_endpoint', '')
            if mgmt_endpoint and vault.lifecycle_state == 'ACTIVE':
                try:
                    key_config = dict(config_dict)
                    key_config['service_endpoint'] = mgmt_endpoint
                    key_client = oci.key_management.KmsManagementClient(key_config, signer=signer)
                    keys_resp = oci.pagination.list_call_get_all_results(
                        key_client.list_keys, compartment_id=tenancy_id)
                    for key in keys_resp.data:
                        kitem = {
                            'id': key.id, 'display_name': key.display_name,
                            'vault_id': vault.id,
                            'lifecycle_state': key.lifecycle_state,
                            'algorithm': getattr(getattr(key, 'key_shape', None), 'algorithm', ''),
                            'resource_type': 'oci.key_management/Key',
                            '_discovery_id': 'oci.key_management.list_keys',
                        }
                        enriched = _enrich_oci_item(kitem)
                        resources.append(enriched)
                        dup = dict(enriched); dup['_discovery_id'] = 'oci.kms.list_keys'
                        resources.append(dup)

                        # Key versions
                        try:
                            ver_resp = oci.pagination.list_call_get_all_results(
                                key_client.list_key_versions, key_id=key.id)
                            for ver in ver_resp.data:
                                vitem = {
                                    'id': ver.id, 'key_id': key.id, 'vault_id': vault.id,
                                    'lifecycle_state': ver.lifecycle_state,
                                    'time_created': str(getattr(ver, 'time_created', '')),
                                    'resource_type': 'oci.key_management/KeyVersion',
                                    '_discovery_id': 'oci.kms.get_key_version',
                                }
                                resources.append(_enrich_oci_item(vitem))
                        except Exception:
                            pass
                except Exception as ke:
                    logger.debug(f"OCI key_management list_keys for vault {vault.id}: {ke}")
    except Exception as e:
        logger.warning(f"OCI key_management list_vaults failed: {e}")

    logger.info(f"  key_management/{region}: {len(resources)} KMS resources found")
    return resources


@oci_handler('load_balancer')
def _scan_load_balancer(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI load balancers, backend sets, and routing policies."""
    import oci
    lb_client = oci.load_balancer.LoadBalancerClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(lb_client.list_load_balancers, compartment_id=tenancy_id)
        for lb in resp.data:
            backend_sets = getattr(lb, 'backend_sets', {}) or {}
            item = {
                'id': lb.id, 'display_name': lb.display_name,
                'lifecycle_state': lb.lifecycle_state,
                'shape_name': getattr(lb, 'shape_name', ''),
                'is_private': getattr(lb, 'is_private', False),
                'ip_addresses': [getattr(ip, 'ip_address', '') for ip in (getattr(lb, 'ip_addresses', []) or [])],
                'backend_sets': list(backend_sets.keys()),
                'resource_type': 'oci.load_balancer/LoadBalancer',
                '_discovery_id': 'oci.load_balancer.list_load_balancers',
            }
            resources.append(_enrich_oci_item(item))

            # Backend sets
            for bs_name, bs in backend_sets.items():
                bs_item = {
                    'id': f"{lb.id}/backend_sets/{bs_name}",
                    'load_balancer_id': lb.id, 'name': bs_name,
                    'policy': getattr(bs, 'policy', ''),
                    'health_checker': str(getattr(bs, 'health_checker', '')),
                    'resource_type': 'oci.load_balancer/BackendSet',
                    '_discovery_id': 'oci.load_balancer.list_backend_sets',
                }
                resources.append(_enrich_oci_item(bs_item))

            # Routing policies
            routing_policies = getattr(lb, 'routing_policies', {}) or {}
            for rp_name, rp in routing_policies.items():
                rp_item = {
                    'id': f"{lb.id}/routing_policies/{rp_name}",
                    'load_balancer_id': lb.id, 'name': rp_name,
                    'condition_language_version': getattr(rp, 'condition_language_version', ''),
                    'resource_type': 'oci.load_balancer/RoutingPolicy',
                    '_discovery_id': 'oci.load_balancer.get_routing_policy',
                }
                resources.append(_enrich_oci_item(rp_item))
    except Exception as e:
        logger.warning(f"OCI load_balancer list_load_balancers failed: {e}")

    logger.info(f"  load_balancer/{region}: {len(resources)} LB resources found")
    return resources


@oci_handler('block_storage')
def _scan_block_storage(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI block volumes, backups, boot volumes, and replicas."""
    import oci
    bs_client = oci.core.BlockstorageClient(config_dict, signer=signer)
    resources = []

    # Volume backups
    try:
        resp = oci.pagination.list_call_get_all_results(bs_client.list_volume_backups, compartment_id=tenancy_id)
        for backup in resp.data:
            item = {
                'id': backup.id, 'display_name': backup.display_name,
                'volume_id': getattr(backup, 'volume_id', ''),
                'lifecycle_state': backup.lifecycle_state,
                'type': getattr(backup, 'type', ''),
                'time_created': str(backup.time_created),
                'resource_type': 'oci.core/VolumeBackup',
                '_discovery_id': 'oci.block_storage.list_volume_backups',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI block_storage list_volume_backups failed: {e}")

    # Boot volumes (need availability_domain)
    try:
        import oci as oci_mod
        identity_client = oci_mod.identity.IdentityClient(config_dict, signer=signer)
        ads = identity_client.list_availability_domains(compartment_id=tenancy_id).data
        for ad in ads:
            try:
                resp = oci.pagination.list_call_get_all_results(
                    bs_client.list_boot_volumes,
                    availability_domain=ad.name,
                    compartment_id=tenancy_id)
                for bv in resp.data:
                    item = {
                        'id': bv.id, 'display_name': bv.display_name,
                        'availability_domain': bv.availability_domain,
                        'lifecycle_state': bv.lifecycle_state,
                        'size_in_gbs': getattr(bv, 'size_in_gbs', 0),
                        'resource_type': 'oci.core/BootVolume',
                        '_discovery_id': 'oci.block_storage.list_boot_volumes',
                    }
                    resources.append(_enrich_oci_item(item))
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"OCI block_storage list_boot_volumes failed: {e}")

    # Volume backup policies
    try:
        resp = oci.pagination.list_call_get_all_results(bs_client.list_volume_backup_policies,
                                                        compartment_id=tenancy_id)
        for policy in resp.data:
            item = {
                'id': policy.id, 'display_name': policy.display_name,
                'time_created': str(getattr(policy, 'time_created', '')),
                'resource_type': 'oci.core/VolumeBackupPolicy',
                '_discovery_id': 'oci.block_storage.get_volume_backup_policy',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI block_storage list_volume_backup_policies failed: {e}")

    logger.info(f"  block_storage/{region}: {len(resources)} block storage resources found")
    return resources


@oci_handler('streaming')
def _scan_streaming(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI Streaming streams."""
    import oci
    stream_admin = oci.streaming.StreamAdminClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(stream_admin.list_streams, compartment_id=tenancy_id)
        for stream in resp.data:
            item = {
                'id': stream.id, 'name': stream.name,
                'lifecycle_state': stream.lifecycle_state,
                'partitions': getattr(stream, 'partitions', 1),
                'retention_in_hours': getattr(stream, 'retention_in_hours', 24),
                'stream_pool_id': getattr(stream, 'stream_pool_id', ''),
                'freeform_tags': stream.freeform_tags or {},
                'resource_type': 'oci.streaming/Stream',
                '_discovery_id': 'oci.streaming.list_streams',
            }
            enriched = _enrich_oci_item(item)
            resources.append(enriched)
            dup = dict(enriched); dup['_discovery_id'] = 'oci.streaming.stream.list'
            resources.append(dup)
    except Exception as e:
        logger.warning(f"OCI streaming list_streams failed: {e}")

    logger.info(f"  streaming/{region}: {len(resources)} streams found")
    return resources


@oci_handler('mysql')
def _scan_mysql(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI MySQL DB systems."""
    import oci
    mysql_client = oci.mysql.DbSystemClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(mysql_client.list_db_systems, compartment_id=tenancy_id)
        for db in resp.data:
            item = {
                'id': db.id, 'display_name': db.display_name,
                'lifecycle_state': db.lifecycle_state,
                'mysql_version': getattr(db, 'mysql_version', ''),
                'availability_domain': getattr(db, 'availability_domain', ''),
                'subnet_id': getattr(db, 'subnet_id', ''),
                'is_highly_available': getattr(db, 'is_highly_available', False),
                'backup_policy': str(getattr(db, 'backup_policy', '')),
                'freeform_tags': db.freeform_tags or {},
                'resource_type': 'oci.mysql/DbSystem',
                '_discovery_id': 'oci.mysql.list_db_systems',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI mysql list_db_systems failed: {e}")

    logger.info(f"  mysql/{region}: {len(resources)} MySQL systems found")
    return resources


@oci_handler('events')
def _scan_events(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI event rules."""
    import oci
    events_client = oci.events.EventsClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(events_client.list_rules, compartment_id=tenancy_id)
        for rule in resp.data:
            item = {
                'id': rule.id, 'display_name': rule.display_name,
                'lifecycle_state': rule.lifecycle_state,
                'is_enabled': getattr(rule, 'is_enabled', False),
                'condition': getattr(rule, 'condition', ''),
                'actions': str(getattr(rule, 'actions', '')),
                'resource_type': 'oci.events/Rule',
                '_discovery_id': 'oci.events.list_rules',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI events list_rules failed: {e}")

    logger.info(f"  events/{region}: {len(resources)} event rules found")
    return resources


@oci_handler('file_storage')
def _scan_file_storage(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI file systems, mount targets, and exports."""
    import oci
    fs_client = oci.file_storage.FileStorageClient(config_dict, signer=signer)
    resources = []

    # Exports (don't need AD)
    try:
        resp = oci.pagination.list_call_get_all_results(fs_client.list_exports, compartment_id=tenancy_id)
        for export in resp.data:
            item = {
                'id': export.id, 'path': getattr(export, 'path', ''),
                'file_system_id': getattr(export, 'file_system_id', ''),
                'export_set_id': getattr(export, 'export_set_id', ''),
                'lifecycle_state': export.lifecycle_state,
                'resource_type': 'oci.file_storage/Export',
                '_discovery_id': 'oci.file_storage.list_exports',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI file_storage list_exports failed: {e}")

    # File systems and mount targets (need AD)
    try:
        import oci as oci_mod
        identity_client = oci_mod.identity.IdentityClient(config_dict, signer=signer)
        ads = identity_client.list_availability_domains(compartment_id=tenancy_id).data
        for ad in ads:
            try:
                resp = oci.pagination.list_call_get_all_results(
                    fs_client.list_file_systems,
                    compartment_id=tenancy_id, availability_domain=ad.name)
                for fs in resp.data:
                    item = {
                        'id': fs.id, 'display_name': fs.display_name,
                        'availability_domain': fs.availability_domain,
                        'lifecycle_state': fs.lifecycle_state,
                        'metered_bytes': getattr(fs, 'metered_bytes', 0),
                        'resource_type': 'oci.file_storage/FileSystem',
                        '_discovery_id': 'oci.file_storage.list_file_systems',
                    }
                    resources.append(_enrich_oci_item(item))
            except Exception:
                pass

            try:
                resp = oci.pagination.list_call_get_all_results(
                    fs_client.list_mount_targets,
                    compartment_id=tenancy_id, availability_domain=ad.name)
                for mt in resp.data:
                    item = {
                        'id': mt.id, 'display_name': mt.display_name,
                        'availability_domain': mt.availability_domain,
                        'lifecycle_state': mt.lifecycle_state,
                        'subnet_id': getattr(mt, 'subnet_id', ''),
                        'resource_type': 'oci.file_storage/MountTarget',
                        '_discovery_id': 'oci.file_storage.list_mount_targets',
                    }
                    resources.append(_enrich_oci_item(item))
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"OCI file_storage AD iteration failed: {e}")

    logger.info(f"  file_storage/{region}: {len(resources)} file storage resources found")
    return resources


@oci_handler('functions')
def _scan_functions(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI function applications."""
    import oci
    fn_client = oci.functions.FunctionsManagementClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(fn_client.list_applications, compartment_id=tenancy_id)
        for app in resp.data:
            item = {
                'id': app.id, 'display_name': app.display_name,
                'lifecycle_state': app.lifecycle_state,
                'subnet_ids': getattr(app, 'subnet_ids', []) or [],
                'config': getattr(app, 'config', {}) or {},
                'freeform_tags': app.freeform_tags or {},
                'resource_type': 'oci.functions/Application',
                '_discovery_id': 'oci.functions.list_applications',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI functions list_applications failed: {e}")

    # PBF listings
    try:
        resp = oci.pagination.list_call_get_all_results(fn_client.list_pbf_listings)
        for listing in resp.data:
            item = {
                'id': listing.id, 'name': listing.name,
                'lifecycle_state': listing.lifecycle_state,
                'resource_type': 'oci.functions/PbfListing',
                '_discovery_id': 'oci.functions.get_pbf_listing',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.debug(f"OCI functions list_pbf_listings failed: {e}")

    logger.info(f"  functions/{region}: {len(resources)} function resources found")
    return resources


@oci_handler('monitoring')
def _scan_monitoring(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI monitoring alarms."""
    import oci
    mon_client = oci.monitoring.MonitoringClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(mon_client.list_alarms, compartment_id=tenancy_id)
        for alarm in resp.data:
            item = {
                'id': alarm.id, 'display_name': alarm.display_name,
                'lifecycle_state': alarm.lifecycle_state,
                'is_enabled': getattr(alarm, 'is_enabled', False),
                'namespace': getattr(alarm, 'namespace', ''),
                'query': getattr(alarm, 'query', ''),
                'severity': getattr(alarm, 'severity', ''),
                'resource_type': 'oci.monitoring/Alarm',
                '_discovery_id': 'oci.monitoring.list_alarms',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI monitoring list_alarms failed: {e}")

    logger.info(f"  monitoring/{region}: {len(resources)} alarms found")
    return resources


@oci_handler('ons')
def _scan_ons(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI notification topics and subscriptions."""
    import oci
    cp_client = oci.ons.NotificationControlPlaneClient(config_dict, signer=signer)
    dp_client = oci.ons.NotificationDataPlaneClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(cp_client.list_topics, compartment_id=tenancy_id)
        for topic in resp.data:
            item = {
                'id': topic.topic_id, 'name': topic.name,
                'lifecycle_state': topic.lifecycle_state,
                'description': getattr(topic, 'description', ''),
                'api_endpoint': getattr(topic, 'api_endpoint', ''),
                'freeform_tags': topic.freeform_tags or {},
                'resource_type': 'oci.ons/NotificationTopic',
                '_discovery_id': 'oci.ons.list_topics',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI ons list_topics failed: {e}")

    try:
        resp = oci.pagination.list_call_get_all_results(dp_client.list_subscriptions, compartment_id=tenancy_id)
        for sub in resp.data:
            item = {
                'id': sub.id, 'topic_id': sub.topic_id,
                'protocol': getattr(sub, 'protocol', ''),
                'endpoint': getattr(sub, 'endpoint', ''),
                'lifecycle_state': sub.lifecycle_state,
                'resource_type': 'oci.ons/Subscription',
                '_discovery_id': 'oci.ons.list_subscriptions',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI ons list_subscriptions failed: {e}")

    logger.info(f"  ons/{region}: {len(resources)} notification resources found")
    return resources


@oci_handler('nosql')
def _scan_nosql(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI NoSQL tables."""
    import oci
    nosql_client = oci.nosql.NosqlClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(nosql_client.list_tables, compartment_id=tenancy_id)
        for table in resp.data:
            item = {
                'id': table.id, 'name': table.name,
                'lifecycle_state': table.lifecycle_state,
                'time_created': str(getattr(table, 'time_created', '')),
                'freeform_tags': table.freeform_tags or {},
                'resource_type': 'oci.nosql/Table',
                '_discovery_id': 'oci.nosql.list_tables',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI nosql list_tables failed: {e}")

    logger.info(f"  nosql/{region}: {len(resources)} NoSQL tables found")
    return resources


@oci_handler('redis')
def _scan_redis(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI Redis clusters."""
    import oci
    try:
        redis_client = oci.redis.RedisClusterClient(config_dict, signer=signer)
    except AttributeError:
        logger.debug("OCI Redis client not available in this SDK version")
        return []
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(redis_client.list_redis_clusters, compartment_id=tenancy_id)
        for cluster in resp.data:
            item = {
                'id': cluster.id, 'display_name': cluster.display_name,
                'lifecycle_state': cluster.lifecycle_state,
                'node_count': getattr(cluster, 'node_count', 0),
                'node_memory_in_gbs': getattr(cluster, 'node_memory_in_gbs', 0),
                'redis_version': getattr(cluster, 'redis_version', ''),
                'freeform_tags': cluster.freeform_tags or {},
                'resource_type': 'oci.redis/RedisCluster',
                '_discovery_id': 'oci.redis.list_redis_clusters',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI redis list_redis_clusters failed: {e}")

    logger.info(f"  redis/{region}: {len(resources)} Redis clusters found")
    return resources


@oci_handler('queue')
def _scan_queue(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI queues."""
    import oci
    try:
        queue_client = oci.queue.QueueAdminClient(config_dict, signer=signer)
    except AttributeError:
        logger.debug("OCI Queue client not available in this SDK version")
        return []
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(queue_client.list_queues, compartment_id=tenancy_id)
        for q in resp.data:
            item = {
                'id': q.id, 'display_name': q.display_name,
                'lifecycle_state': q.lifecycle_state,
                'freeform_tags': q.freeform_tags or {},
                'resource_type': 'oci.queue/Queue',
                '_discovery_id': 'oci.queue.list_queues',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI queue list_queues failed: {e}")

    logger.info(f"  queue/{region}: {len(resources)} queues found")
    return resources


@oci_handler('resource_manager')
def _scan_resource_manager(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI Resource Manager stacks."""
    import oci
    rm_client = oci.resource_manager.ResourceManagerClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(rm_client.list_stacks, compartment_id=tenancy_id)
        for stack in resp.data:
            item = {
                'id': stack.id, 'display_name': stack.display_name,
                'lifecycle_state': stack.lifecycle_state,
                'time_created': str(getattr(stack, 'time_created', '')),
                'freeform_tags': stack.freeform_tags or {},
                'resource_type': 'oci.resource_manager/Stack',
                '_discovery_id': 'oci.resource_manager.list_stacks',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI resource_manager list_stacks failed: {e}")

    logger.info(f"  resource_manager/{region}: {len(resources)} stacks found")
    return resources


@oci_handler('dns')
def _scan_dns(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI DNS zones."""
    import oci
    dns_client = oci.dns.DnsClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(dns_client.list_zones, compartment_id=tenancy_id)
        for zone in resp.data:
            item = {
                'id': zone.id, 'name': zone.name,
                'zone_type': getattr(zone, 'zone_type', ''),
                'lifecycle_state': zone.lifecycle_state,
                'serial': getattr(zone, 'serial', 0),
                'freeform_tags': zone.freeform_tags or {},
                'resource_type': 'oci.dns/Zone',
                '_discovery_id': 'oci.dns.list_zones',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI dns list_zones failed: {e}")

    # Zone transfer servers (global)
    try:
        resp = dns_client.list_zone_transfer_servers(compartment_id=tenancy_id)
        for server in (resp.data or []):
            item = {
                'id': getattr(server, 'address', 'zone_transfer_server'),
                'address': getattr(server, 'address', ''),
                'port': getattr(server, 'port', 53),
                'is_transfer_destination': getattr(server, 'is_transfer_destination', False),
                'resource_type': 'oci.dns/ZoneTransferServer',
                '_discovery_id': 'oci.dns.list_zone_transfer_servers',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.debug(f"OCI dns list_zone_transfer_servers failed: {e}")

    logger.info(f"  dns/{region}: {len(resources)} DNS resources found")
    return resources


@oci_handler('waf')
def _scan_waf(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI WAF policies."""
    import oci
    waf_client = oci.waf.WafClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(waf_client.list_web_app_firewall_policies, compartment_id=tenancy_id)
        for policy in resp.data:
            item = {
                'id': policy.id, 'display_name': policy.display_name,
                'lifecycle_state': policy.lifecycle_state,
                'time_created': str(getattr(policy, 'time_created', '')),
                'freeform_tags': policy.freeform_tags or {},
                'resource_type': 'oci.waf/WebAppFirewallPolicy',
                '_discovery_id': 'oci.waf.list_web_app_firewall_policies',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI waf list_web_app_firewall_policies failed: {e}")

    logger.info(f"  waf/{region}: {len(resources)} WAF policies found")
    return resources


@oci_handler('cloud_guard')
def _scan_cloud_guard(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI Cloud Guard targets."""
    import oci
    if region and region not in ('us-ashburn-1', 'us-phoenix-1', 'global', ''):
        return []  # Cloud Guard is region-specific but often home-region only
    cg_client = oci.cloud_guard.CloudGuardClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(cg_client.list_targets, compartment_id=tenancy_id)
        for target in resp.data:
            item = {
                'id': target.id, 'display_name': target.display_name,
                'lifecycle_state': target.lifecycle_state,
                'target_resource_type': getattr(target, 'target_resource_type', ''),
                'target_resource_id': getattr(target, 'target_resource_id', ''),
                'freeform_tags': target.freeform_tags or {},
                'resource_type': 'oci.cloud_guard/Target',
                '_discovery_id': 'oci.cloud_guard.list_targets',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI cloud_guard list_targets failed: {e}")

    logger.info(f"  cloud_guard/{region}: {len(resources)} Cloud Guard targets found")
    return resources


@oci_handler('data_safe')
def _scan_data_safe(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI Data Safe configuration and target databases."""
    import oci
    ds_client = oci.data_safe.DataSafeClient(config_dict, signer=signer)
    resources = []

    # Data Safe configuration
    try:
        cfg = ds_client.get_data_safe_configuration(compartment_id=tenancy_id).data
        item = {
            'id': f"{tenancy_id}/data_safe_configuration",
            'compartment_id': tenancy_id,
            'is_enabled': getattr(cfg, 'is_enabled', False),
            'lifecycle_state': getattr(cfg, 'lifecycle_state', ''),
            'resource_type': 'oci.data_safe/Configuration',
            '_discovery_id': 'oci.data_safe.get_data_safe_configuration',
        }
        resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI data_safe get_data_safe_configuration failed: {e}")

    # Target databases
    try:
        resp = oci.pagination.list_call_get_all_results(ds_client.list_target_databases, compartment_id=tenancy_id)
        for db in resp.data:
            item = {
                'id': db.id, 'display_name': db.display_name,
                'lifecycle_state': db.lifecycle_state,
                'database_type': getattr(db, 'database_type', ''),
                'freeform_tags': db.freeform_tags or {},
                'resource_type': 'oci.data_safe/TargetDatabase',
                '_discovery_id': 'oci.data_safe.list_target_databases',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI data_safe list_target_databases failed: {e}")

    logger.info(f"  data_safe/{region}: {len(resources)} Data Safe resources found")
    return resources


@oci_handler('certificates')
def _scan_certificates(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI certificates and certificate authorities."""
    import oci
    try:
        cert_client = oci.certificates_management.CertificatesManagementClient(config_dict, signer=signer)
    except AttributeError:
        logger.debug("OCI Certificates Management client not available")
        return []
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(cert_client.list_certificates, compartment_id=tenancy_id)
        for cert in resp.data:
            item = {
                'id': cert.id, 'name': cert.name,
                'lifecycle_state': cert.lifecycle_state,
                'config_type': getattr(cert, 'config_type', ''),
                'time_created': str(getattr(cert, 'time_created', '')),
                'freeform_tags': cert.freeform_tags or {},
                'resource_type': 'oci.certificates_management/Certificate',
                '_discovery_id': 'oci.certificates.list_certificates',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI certificates list_certificates failed: {e}")

    try:
        resp = oci.pagination.list_call_get_all_results(cert_client.list_certificate_authorities, compartment_id=tenancy_id)
        for ca in resp.data:
            item = {
                'id': ca.id, 'name': ca.name,
                'lifecycle_state': ca.lifecycle_state,
                'config_type': getattr(ca, 'config_type', ''),
                'freeform_tags': ca.freeform_tags or {},
                'resource_type': 'oci.certificates_management/CertificateAuthority',
                '_discovery_id': 'oci.certificates.list_certificate_authorities',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI certificates list_certificate_authorities failed: {e}")

    logger.info(f"  certificates/{region}: {len(resources)} certificate resources found")
    return resources


@oci_handler('apigateway')
def _scan_apigateway(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI API gateways, APIs, and deployments."""
    import oci
    gw_client = oci.apigateway.GatewayClient(config_dict, signer=signer)
    api_client_obj = oci.apigateway.ApiClient(config_dict, signer=signer)
    deploy_client = oci.apigateway.DeploymentClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(gw_client.list_gateways, compartment_id=tenancy_id)
        for gw in resp.data:
            item = {
                'id': gw.id, 'display_name': gw.display_name,
                'lifecycle_state': gw.lifecycle_state,
                'endpoint_type': getattr(gw, 'endpoint_type', ''),
                'hostname': getattr(gw, 'hostname', ''),
                'freeform_tags': gw.freeform_tags or {},
                'resource_type': 'oci.apigateway/Gateway',
                '_discovery_id': 'oci.apigateway.list_gateways',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI apigateway list_gateways failed: {e}")

    try:
        resp = oci.pagination.list_call_get_all_results(api_client_obj.list_apis, compartment_id=tenancy_id)
        for api in resp.data:
            item = {
                'id': api.id, 'display_name': api.display_name,
                'lifecycle_state': api.lifecycle_state,
                'freeform_tags': api.freeform_tags or {},
                'resource_type': 'oci.apigateway/Api',
                '_discovery_id': 'oci.apigateway.list_apis',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI apigateway list_apis failed: {e}")

    try:
        resp = oci.pagination.list_call_get_all_results(deploy_client.list_deployments, compartment_id=tenancy_id)
        for dep in resp.data:
            item = {
                'id': dep.id, 'display_name': dep.display_name,
                'gateway_id': getattr(dep, 'gateway_id', ''),
                'lifecycle_state': dep.lifecycle_state,
                'path_prefix': getattr(dep, 'path_prefix', ''),
                'resource_type': 'oci.apigateway/Deployment',
                '_discovery_id': 'oci.apigateway.list_deployments',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI apigateway list_deployments failed: {e}")

    logger.info(f"  apigateway/{region}: {len(resources)} API gateway resources found")
    return resources


@oci_handler('artifacts')
def _scan_artifacts(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI container repositories and image signatures."""
    import oci
    art_client = oci.artifacts.ArtifactsClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(art_client.list_container_repositories, compartment_id=tenancy_id)
        for repo in resp.data:
            item = {
                'id': repo.id, 'display_name': repo.display_name,
                'lifecycle_state': repo.lifecycle_state,
                'is_public': getattr(repo, 'is_public', False),
                'image_count': getattr(repo, 'image_count', 0),
                'freeform_tags': repo.freeform_tags or {},
                'resource_type': 'oci.artifacts/ContainerRepository',
                '_discovery_id': 'oci.artifacts.list_container_repositories',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI artifacts list_container_repositories failed: {e}")

    try:
        resp = oci.pagination.list_call_get_all_results(art_client.list_container_image_signatures, compartment_id=tenancy_id)
        for sig in resp.data:
            item = {
                'id': sig.id, 'image_id': getattr(sig, 'image_id', ''),
                'kms_key_id': getattr(sig, 'kms_key_id', ''),
                'signing_algorithm': getattr(sig, 'signing_algorithm', ''),
                'resource_type': 'oci.artifacts/ContainerImageSignature',
                '_discovery_id': 'oci.artifacts.list_container_image_signatures',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI artifacts list_container_image_signatures failed: {e}")

    logger.info(f"  artifacts/{region}: {len(resources)} artifact resources found")
    return resources


@oci_handler('bds')
def _scan_bds(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI Big Data Service instances."""
    import oci
    bds_client = oci.bds.BdsClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(bds_client.list_bds_instances, compartment_id=tenancy_id)
        for instance in resp.data:
            item = {
                'id': instance.id, 'display_name': instance.display_name,
                'lifecycle_state': instance.lifecycle_state,
                'number_of_nodes': getattr(instance, 'number_of_nodes', 0),
                'cluster_version': getattr(instance, 'cluster_version', ''),
                'is_high_availability': getattr(instance, 'is_high_availability', False),
                'is_secure': getattr(instance, 'is_secure', False),
                'is_cloud_sql_configured': getattr(instance, 'is_cloud_sql_configured', False),
                'freeform_tags': instance.freeform_tags or {},
                'resource_type': 'oci.bds/BdsInstance',
                '_discovery_id': 'oci.bds.list_bds_instances',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI bds list_bds_instances failed: {e}")

    logger.info(f"  bds/{region}: {len(resources)} BDS instances found")
    return resources


@oci_handler('network_firewall')
def _scan_network_firewall(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI network firewalls."""
    import oci
    try:
        nf_client = oci.network_firewall.NetworkFirewallClient(config_dict, signer=signer)
    except AttributeError:
        logger.debug("OCI NetworkFirewall client not available")
        return []
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(nf_client.list_network_firewalls, compartment_id=tenancy_id)
        for fw in resp.data:
            item = {
                'id': fw.id, 'display_name': fw.display_name,
                'lifecycle_state': fw.lifecycle_state,
                'network_firewall_policy_id': getattr(fw, 'network_firewall_policy_id', ''),
                'subnet_id': getattr(fw, 'subnet_id', ''),
                'freeform_tags': fw.freeform_tags or {},
                'resource_type': 'oci.network_firewall/NetworkFirewall',
                '_discovery_id': 'oci.network_firewall.list_network_firewalls',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI network_firewall list_network_firewalls failed: {e}")

    logger.info(f"  network_firewall/{region}: {len(resources)} network firewalls found")
    return resources


@oci_handler('disaster_recovery')
def _scan_disaster_recovery(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI disaster recovery protection groups."""
    import oci
    try:
        dr_client = oci.disaster_recovery.DisasterRecoveryClient(config_dict, signer=signer)
    except AttributeError:
        logger.debug("OCI DisasterRecovery client not available")
        return []
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(dr_client.list_dr_protection_groups, compartment_id=tenancy_id)
        for group in resp.data:
            item = {
                'id': group.id, 'display_name': group.display_name,
                'lifecycle_state': group.lifecycle_state,
                'role': getattr(group, 'role', ''),
                'freeform_tags': group.freeform_tags or {},
                'resource_type': 'oci.disaster_recovery/DrProtectionGroup',
                '_discovery_id': 'oci.disaster_recovery.list_dr_protection_groups',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI disaster_recovery list_dr_protection_groups failed: {e}")

    logger.info(f"  disaster_recovery/{region}: {len(resources)} DR groups found")
    return resources


@oci_handler('analytics')
def _scan_analytics(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI Analytics instances."""
    import oci
    analytics_client = oci.analytics.AnalyticsClient(config_dict, signer=signer)
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(analytics_client.list_analytics_instances, compartment_id=tenancy_id)
        for instance in resp.data:
            item = {
                'id': instance.id, 'name': instance.name,
                'lifecycle_state': instance.lifecycle_state,
                'feature_set': getattr(instance, 'feature_set', ''),
                'capacity': str(getattr(instance, 'capacity', '')),
                'freeform_tags': instance.freeform_tags or {},
                'resource_type': 'oci.analytics/AnalyticsInstance',
                '_discovery_id': 'oci.analytics.list_analytics_instances',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI analytics list_analytics_instances failed: {e}")

    logger.info(f"  analytics/{region}: {len(resources)} analytics instances found")
    return resources


@oci_handler('container_instances')
def _scan_container_instances(config_dict, signer, tenancy_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover OCI container instances."""
    import oci
    try:
        ci_client = oci.container_instances.ContainerInstanceClient(config_dict, signer=signer)
    except AttributeError:
        logger.debug("OCI ContainerInstance client not available")
        return []
    resources = []

    try:
        resp = oci.pagination.list_call_get_all_results(ci_client.list_container_instances, compartment_id=tenancy_id)
        for ci in resp.data:
            item = {
                'id': ci.id, 'display_name': ci.display_name,
                'lifecycle_state': ci.lifecycle_state,
                'container_count': getattr(ci, 'container_count', 0),
                'availability_domain': getattr(ci, 'availability_domain', ''),
                'freeform_tags': ci.freeform_tags or {},
                'resource_type': 'oci.container_instances/ContainerInstance',
                '_discovery_id': 'oci.container_instances.list_container_instances',
            }
            resources.append(_enrich_oci_item(item))
    except Exception as e:
        logger.warning(f"OCI container_instances list_container_instances failed: {e}")

    logger.info(f"  container_instances/{region}: {len(resources)} container instances found")
    return resources


# ─── Scanner Class ──────────────────────────────────────────────────

class OCIDiscoveryScanner(DiscoveryScanner):
    """
    OCI-specific discovery scanner implementation.

    Uses handler registry pattern: OCI_SERVICE_HANDLERS maps service names
    to handler functions. Add new services by decorating with @oci_handler.
    """

    def __init__(self, credentials: Dict[str, Any], **kwargs):
        super().__init__(credentials, **kwargs)
        self.oci_config = None
        self.signer = None
        # Extract tenancy_id from top level or nested credentials
        self.tenancy_id = (
            credentials.get('tenancy_id')
            or credentials.get('tenancy_ocid')
            or credentials.get('account_id')
            or (credentials.get('credentials') or {}).get('tenancy_id')
            or (credentials.get('credentials') or {}).get('tenancy_ocid')
        )

    def authenticate(self) -> Any:
        """
        Authenticate to OCI using provided credentials.

        Supports:
        - API Key (user OCID, fingerprint, private key)
        - Instance Principal
        """
        try:
            import oci

            cred_type = self.credentials.get('credential_type', '').lower()

            # Support nested credentials (Secrets Manager wrapper)
            creds = self.credentials
            if 'credentials' in creds and isinstance(creds['credentials'], dict):
                inner = creds['credentials']
                if inner.get('user_ocid') or inner.get('tenancy_ocid'):
                    creds = {**creds, **inner}

            if cred_type in ('api_key', 'oci_user_principal', 'oci_api_key'):
                user_ocid = creds.get('user_ocid')
                tenancy_ocid = creds.get('tenancy_ocid') or creds.get('tenancy_id')
                fingerprint = creds.get('fingerprint')
                private_key = creds.get('private_key')
                region = creds.get('region', 'us-ashburn-1')

                if not self.tenancy_id:
                    self.tenancy_id = tenancy_ocid

                self.oci_config = {
                    'user': user_ocid,
                    'key_content': private_key,
                    'fingerprint': fingerprint,
                    'tenancy': tenancy_ocid,
                    'region': region,
                }

                self.signer = oci.signer.Signer(
                    tenancy=tenancy_ocid,
                    user=user_ocid,
                    fingerprint=fingerprint,
                    private_key_file_location=None,
                    pass_phrase=None,
                    private_key_content=private_key,
                )

                logger.info("OCI authentication successful (API Key)")

            elif cred_type == 'instance_principal':
                from oci.auth.signers import InstancePrincipalsSecurityTokenSigner
                self.signer = InstancePrincipalsSecurityTokenSigner()
                self.oci_config = {}
                logger.info("OCI authentication successful (Instance Principal)")

            else:
                raise AuthenticationError(f"Unsupported OCI credential type: {cred_type}")

            return self.signer

        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"OCI authentication failed: {e}")
            raise AuthenticationError(f"OCI authentication failed: {e}")

    async def scan_service(
        self,
        service: str,
        region: str,
        config: Dict[str, Any],
        skip_dependents: bool = False,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Execute OCI service discovery via registered handler."""
        handler = OCI_SERVICE_HANDLERS.get(service)
        if not handler:
            logger.warning(f"No OCI handler registered for service: {service}")
            return ([], {'service': service, 'status': 'no_handler'})

        # Update config region for this scan
        scan_config = dict(self.oci_config) if self.oci_config else {}
        scan_config['region'] = region

        loop = asyncio.get_event_loop()
        try:
            discoveries = await loop.run_in_executor(
                _OCI_EXECUTOR,
                handler,
                scan_config,        # OCI config dict
                self.signer,         # OCI signer
                self.tenancy_id,     # compartment/tenancy ID
                region,
                config
            )
            metadata = {
                'service': service,
                'region': region,
                'resources_found': len(discoveries),
                'status': 'completed'
            }
            return (discoveries, metadata)
        except Exception as e:
            logger.error(f"OCI {service}/{region} scan failed: {e}")
            return ([], {'service': service, 'status': 'error', 'error': str(e)})

    def get_client(self, service: str, region: str) -> Any:
        """Get OCI SDK client for specific service."""
        import oci
        config = dict(self.oci_config) if self.oci_config else {}
        config['region'] = region
        client_map = {
            'compute': oci.core.ComputeClient,
            'database': oci.database.DatabaseClient,
            'object_storage': oci.object_storage.ObjectStorageClient,
            'audit': oci.audit.AuditClient,
        }
        client_class = client_map.get(service)
        if not client_class:
            raise DiscoveryError(f"No OCI client mapping for service: {service}")
        return client_class(config, signer=self.signer)

    def extract_resource_identifier(
        self,
        item: Dict[str, Any],
        service: str,
        region: str,
        account_id: str,
        resource_type: Optional[str] = None
    ) -> Dict[str, str]:
        """Extract resource identifiers from OCI response (OCID-based)."""
        ocid = item.get('id', '')
        resource_name = item.get('display_name', item.get('name', ''))
        return {
            'resource_arn': ocid,
            'resource_id': ocid,
            'resource_name': resource_name,
            'resource_uid': ocid,
            'resource_type': resource_type or item.get('resource_type', ''),
        }

    def get_service_client_name(self, service: str) -> str:
        """Map service name to OCI SDK client name."""
        return f"oci.{service}"

    async def list_available_regions(self) -> List[str]:
        """Dynamically list OCI regions; falls back to defaults."""
        try:
            import oci
            identity_client = oci.identity.IdentityClient(
                self.oci_config, signer=self.signer
            )
            regions = identity_client.list_regions().data
            return [r.name for r in regions]
        except Exception as e:
            logger.warning(f"Failed to list OCI regions: {e}; using defaults")
            return DEFAULT_OCI_REGIONS

    def get_account_id(self) -> str:
        """Return OCI tenancy OCID."""
        return self.tenancy_id or ''
