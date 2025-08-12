from typing import Any, Dict, List, Optional

from kubernetes import client


class ActionRegistry:
    def __init__(self, api_client: client.ApiClient, v1_api: client.CoreV1Api, inventory: Optional[Dict[str, Any]] = None, mocks: Optional[Dict[str, Any]] = None):
        self.api_client = api_client
        self.v1 = v1_api
        self.rbac = client.RbacAuthorizationV1Api(api_client) if api_client else None
        self.apps = client.AppsV1Api(api_client) if api_client else None
        self.inventory = inventory or {}
        self.mocks = mocks or {}

    def execute(self, action: str, params: Optional[Dict[str, Any]] = None) -> Any:
        params = params or {}
        if action == 'get_apiserver_config':
            if 'config' in params:
                return params['config']
            return self._get_component_config(component='kube-apiserver')
        if action == 'get_component_config':
            if 'config' in params:
                return params['config']
            component = params.get('component')
            if component and component in self.mocks:
                return self.mocks[component]
            return self._get_component_config(component=component)
        # Serve mocks for list/get actions when available (flat and nested forms)
        if action in {
            'list_namespaces', 'list_cluster_roles', 'list_cluster_role_bindings',
            'list_roles', 'list_role_bindings', 'list_pods', 'list_deployments', 'list_statefulsets'
        }:
            # flat direct mock
            if action in self.mocks:
                return self.mocks[action]
            # core pods mock
            if action == 'list_pods' and 'core' in self.mocks and isinstance(self.mocks['core'], list):
                return self.mocks['core']
            # rbac mocks stored under 'rbac' object keyed by action name
            if 'rbac' in self.mocks and isinstance(self.mocks['rbac'], dict) and action in self.mocks['rbac']:
                return self.mocks['rbac'][action]
        if action == 'list_namespaces':
            return self._list_namespaces()
        if action == 'list_cluster_roles':
            return self._list_cluster_roles()
        if action == 'list_cluster_role_bindings':
            return self._list_cluster_role_bindings()
        if action == 'list_roles':
            namespace = params.get('namespace')
            return self._list_roles(namespace)
        if action == 'list_role_bindings':
            namespace = params.get('namespace')
            return self._list_role_bindings(namespace)
        if action == 'list_pods':
            namespace = params.get('namespace')
            return self._list_pods(namespace)
        if action == 'list_deployments':
            namespace = params.get('namespace')
            return self._list_deployments(namespace)
        if action == 'list_statefulsets':
            namespace = params.get('namespace')
            return self._list_statefulsets(namespace)
        if action == 'get_cluster_info':
            return self.inventory.get('cluster_info', {})
        if action == 'get_provider':
            return self.inventory.get('cluster_info', {}).get('provider')
        if action == 'is_managed_control_plane':
            return bool(self.inventory.get('cluster_info', {}).get('managed_control_plane'))
        if action == 'identity':
            return params
        return params

    def _list_namespaces(self) -> List[Dict[str, Any]]:
        items = self.v1.list_namespace().items
        return [
            {
                'name': ns.metadata.name,
                'labels': ns.metadata.labels or {},
                'annotations': ns.metadata.annotations or {},
                'status': ns.status.phase,
                'uid': ns.metadata.uid,
            }
            for ns in items
        ]

    def _list_cluster_roles(self) -> List[Dict[str, Any]]:
        if not self.rbac:
            return []
        items = self.rbac.list_cluster_role().items
        roles: List[Dict[str, Any]] = []
        for cr in items:
            rules = []
            for r in cr.rules or []:
                rules.append({
                    'api_groups': r.api_groups or [],
                    'resources': r.resources or [],
                    'verbs': r.verbs or [],
                    'non_resource_urls': r.non_resource_urls or [],
                })
            roles.append({
                'name': cr.metadata.name,
                'labels': cr.metadata.labels or {},
                'annotations': cr.metadata.annotations or {},
                'rules': rules,
            })
        return roles

    def _list_cluster_role_bindings(self) -> List[Dict[str, Any]]:
        if not self.rbac:
            return []
        items = self.rbac.list_cluster_role_binding().items
        crbs: List[Dict[str, Any]] = []
        for rb in items:
            subjects = []
            for s in rb.subjects or []:
                subjects.append({
                    'kind': s.kind,
                    'name': s.name,
                    'namespace': s.namespace,
                })
            crbs.append({
                'name': rb.metadata.name,
                'role_ref': {
                    'api_group': rb.role_ref.api_group,
                    'kind': rb.role_ref.kind,
                    'name': rb.role_ref.name,
                },
                'subjects': subjects,
            })
        return crbs

    def _list_roles(self, namespace: Optional[str]) -> List[Dict[str, Any]]:
        if not self.rbac:
            return []
        items = self.rbac.list_namespaced_role(namespace=namespace).items if namespace else self.rbac.list_role_for_all_namespaces().items
        roles: List[Dict[str, Any]] = []
        for r in items:
            rules = []
            for rule in r.rules or []:
                rules.append({
                    'api_groups': rule.api_groups or [],
                    'resources': rule.resources or [],
                    'verbs': rule.verbs or [],
                    'non_resource_urls': rule.non_resource_urls or [],
                })
            roles.append({
                'name': r.metadata.name,
                'namespace': r.metadata.namespace,
                'rules': rules,
            })
        return roles

    def _list_role_bindings(self, namespace: Optional[str]) -> List[Dict[str, Any]]:
        if not self.rbac:
            return []
        items = self.rbac.list_namespaced_role_binding(namespace=namespace).items if namespace else self.rbac.list_role_binding_for_all_namespaces().items
        rbs: List[Dict[str, Any]] = []
        for rb in items:
            subjects = []
            for s in rb.subjects or []:
                subjects.append({
                    'kind': s.kind,
                    'name': s.name,
                    'namespace': s.namespace,
                })
            rbs.append({
                'name': rb.metadata.name,
                'namespace': rb.metadata.namespace,
                'role_ref': {
                    'api_group': rb.role_ref.api_group,
                    'kind': rb.role_ref.kind,
                    'name': rb.role_ref.name,
                },
                'subjects': subjects,
            })
        return rbs

    def _list_pods(self, namespace: Optional[str]) -> List[Dict[str, Any]]:
        items = self.v1.list_namespaced_pod(namespace=namespace).items if namespace else self.v1.list_pod_for_all_namespaces().items
        pods: List[Dict[str, Any]] = []
        for p in items:
            containers = []
            for c in p.spec.containers or []:
                security_context = c.security_context.to_dict() if c.security_context else {}
                env_list = []
                for e in c.env or []:
                    try:
                        env_list.append({'name': e.name, 'value': e.value})
                    except Exception:
                        pass
                ports_list = []
                for prt in c.ports or []:
                    try:
                        ports_list.append({'name': prt.name, 'containerPort': prt.container_port, 'protocol': prt.protocol})
                    except Exception:
                        pass
                containers.append({
                    'name': c.name,
                    'image': c.image,
                    'securityContext': security_context,
                    'resources': (c.resources or {}).to_dict() if c.resources else {},
                    'args': c.args or [],
                    'command': c.command or [],
                    'env': env_list,
                    'ports': ports_list,
                })
            pods.append({
                'name': p.metadata.name,
                'namespace': p.metadata.namespace,
                'labels': p.metadata.labels or {},
                'annotations': p.metadata.annotations or {},
                'hostNetwork': bool(getattr(p.spec, 'host_network', False)),
                'hostPID': bool(getattr(p.spec, 'host_pid', False)),
                'hostIPC': bool(getattr(p.spec, 'host_ipc', False)),
                'containers': containers,
            })
        return pods

    def _list_deployments(self, namespace: Optional[str]) -> List[Dict[str, Any]]:
        if not self.apps:
            return []
        items = self.apps.list_namespaced_deployment(namespace=namespace).items if namespace else self.apps.list_deployment_for_all_namespaces().items
        deployments: List[Dict[str, Any]] = []
        for d in items:
            deployments.append({
                'name': d.metadata.name,
                'namespace': d.metadata.namespace,
                'labels': d.metadata.labels or {},
                'annotations': d.metadata.annotations or {},
                'selector': (d.spec.selector or {}).to_dict() if d.spec.selector else {},
            })
        return deployments

    def _list_statefulsets(self, namespace: Optional[str]) -> List[Dict[str, Any]]:
        if not self.apps:
            return []
        items = self.apps.list_namespaced_stateful_set(namespace=namespace).items if namespace else self.apps.list_stateful_set_for_all_namespaces().items
        ssets: List[Dict[str, Any]] = []
        for s in items:
            ssets.append({
                'name': s.metadata.name,
                'namespace': s.metadata.namespace,
                'labels': s.metadata.labels or {},
                'annotations': s.metadata.annotations or {},
                'selector': (s.spec.selector or {}).to_dict() if s.spec.selector else {},
            })
        return ssets

    def _get_component_config(self, component: Optional[str]) -> List[Dict[str, Any]]:
        if not component:
            return []
        # Common label selectors observed in clusters
        selectors = [
            f"component={component}",
            f"k8s-app={component}",
            f"app={component}",
        ]
        pods = []
        for sel in selectors:
            try:
                pods = self.v1.list_namespaced_pod(namespace="kube-system", label_selector=sel).items
                if pods:
                    break
            except Exception:
                continue
        configs: List[Dict[str, Any]] = []
        for pod in pods:
            for container in pod.spec.containers:
                args = container.args or []
                arg_map: Dict[str, Any] = {}
                i = 0
                while i < len(args):
                    token = args[i]
                    if token.startswith('--') and '=' in token:
                        key, val = token.split('=', 1)
                        arg_map[key.lstrip('-')] = val
                    elif token.startswith('--') and i + 1 < len(args) and not args[i + 1].startswith('--'):
                        key = token.lstrip('-')
                        val = args[i + 1]
                        arg_map[key] = val
                        i += 1
                    i += 1
                configs.append({
                    'pod_name': pod.metadata.name,
                    'namespace': pod.metadata.namespace,
                    'component': component,
                    'arguments': arg_map,
                    # Backward compatibility alias for apiserver yaml already created
                    'apiServerArguments': arg_map if component == 'kube-apiserver' else None,
                })
        return configs

    @staticmethod
    def resolve_path(payload: Any, path_expr: Optional[str]) -> Any:
        if payload is None or not path_expr:
            return None
        target = payload
        segments = [seg for seg in str(path_expr).split('.') if seg]
        for seg in segments:
            if isinstance(target, dict):
                if seg in target:
                    target = target[seg]
                    continue
                alt = seg.replace('_', '-')
                if alt in target:
                    target = target[alt]
                    continue
                return None
            elif isinstance(target, list):
                try:
                    idx = int(seg)
                    target = target[idx]
                except Exception:
                    return None
            else:
                return None
        return target 