from typing import Dict, Any, Optional, List
from kubernetes import client, config
from kubernetes.client.rest import ApiException


def load_kube_api_client(
    kubeconfig: Optional[str] = None,
    context: Optional[str] = None,
    api_client: Optional[client.ApiClient] = None,
) -> client.ApiClient:
    """
    Load Kubernetes API client.
    Preference order: supplied api_client > kubeconfig/context > in-cluster > default kubeconfig.
    """
    if api_client:
        return api_client
    if kubeconfig or context:
        config.load_kube_config(config_file=kubeconfig, context=context)
    else:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
    return client.ApiClient()


def _detect_provider_hints_from_nodes(nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
    provider = "unknown"
    managed = False
    region = None
    zones: List[str] = []

    for node in nodes:
        labels = node.get("labels", {}) or {}
        label_keys = list(labels.keys())
        if any(k.startswith("eks.amazonaws.com") or k.startswith("alpha.eksctl.io") for k in label_keys):
            provider = "aws"
            managed = True
        if any(k.startswith("cloud.google.com") or k.startswith("k8s.gke.io") for k in label_keys):
            provider = "gcp"
            managed = True
        if any(k.startswith("kubernetes.azure.com") or k.startswith("aks") for k in label_keys):
            provider = "azure"
            managed = True
        if any(k.startswith("node.openshift.io") or k.startswith("machine.openshift.io") for k in label_keys):
            if provider == "unknown":
                provider = "ocp"

        region_label = labels.get("topology.kubernetes.io/region") or labels.get("failure-domain.beta.kubernetes.io/region")
        if region_label and not region:
            region = region_label
        zone_label = labels.get("topology.kubernetes.io/zone") or labels.get("failure-domain.beta.kubernetes.io/zone")
        if zone_label:
            zones.append(zone_label)

    return {
        "provider": provider,
        "managed_control_plane": managed,
        "region": region,
        "zones": sorted(list(set(zones))),
    }


def discover_kubernetes_inventory(
    kubeconfig: str = None,
    context: str = None,
    api_client: client.ApiClient = None,
    include_nodes: bool = True,
    include_extra: bool = False,
) -> Dict[str, Any]:
    """
    Discover cluster info, nodes, and namespaces with minimal dependencies.
    Returns a dict suitable for YAML engine metadata and actions.
    """
    api = load_kube_api_client(kubeconfig=kubeconfig, context=context, api_client=api_client)
    v1 = client.CoreV1Api(api)
    version_api = client.VersionApi(api)

    inventory = {
        "cluster_info": {},
        "nodes": [],
        "namespaces": [],
    }

    # Cluster info
    try:
        version = version_api.get_code()
        cluster_uid = None
        try:
            ns = v1.read_namespace("kube-system")
            cluster_uid = ns.metadata.uid
        except Exception:
            pass
        inventory["cluster_info"] = {
            "major": version.major,
            "minor": version.minor,
            "git_version": version.git_version,
            "platform": version.platform,
            "cluster_uid": cluster_uid,
        }
    except Exception as e:
        inventory["cluster_info"] = {"error": str(e)}

    # Nodes
    if include_nodes:
        try:
            node_list = v1.list_node()
            for node in node_list.items:
                node_info = {
                    "name": node.metadata.name,
                    "labels": node.metadata.labels or {},
                    "taints": [t.to_dict() for t in (node.spec.taints or [])],
                    "roles": [k.replace("node-role.kubernetes.io/", "") for k in (node.metadata.labels or {}) if k.startswith("node-role.kubernetes.io/")],
                    "internal_ip": None,
                    "external_ip": None,
                    "os_image": node.status.node_info.os_image,
                    "kubelet_version": node.status.node_info.kubelet_version,
                    "container_runtime": node.status.node_info.container_runtime_version,
                }
                for addr in node.status.addresses:
                    if addr.type == "InternalIP":
                        node_info["internal_ip"] = addr.address
                    elif addr.type == "ExternalIP":
                        node_info["external_ip"] = addr.address
                inventory["nodes"].append(node_info)
        except ApiException as e:
            inventory["nodes"] = [{"error": str(e)}]

    # Provider hints
    try:
        hints = _detect_provider_hints_from_nodes(inventory.get("nodes", []))
        inventory["cluster_info"].update(hints)
    except Exception:
        pass

    # Namespaces
    try:
        ns_list = v1.list_namespace()
        for ns in ns_list.items:
            inventory["namespaces"].append({
                "name": ns.metadata.name,
                "labels": ns.metadata.labels or {},
                "annotations": ns.metadata.annotations or {},
                "status": ns.status.phase,
                "creation_timestamp": str(ns.metadata.creation_timestamp),
                "uid": ns.metadata.uid,
            })
    except ApiException as e:
        inventory["namespaces"] = [{"error": str(e)}]

    return inventory 