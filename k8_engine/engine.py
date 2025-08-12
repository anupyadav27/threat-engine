import os
import time
from typing import Any, Dict, List, Optional

import yaml
import json
from kubernetes import client

from .utils.reporting import CheckResult, CheckStatus, CheckSeverity
from .utils.cluster_namespace_discovery import load_kube_api_client, discover_kubernetes_inventory
from .registry import ActionRegistry
from .operators import evaluate_field_condition


def _load_yaml_files(rules_dir: str) -> List[Dict[str, Any]]:
    yamls: List[Dict[str, Any]] = []
    for root, _dirs, files in os.walk(rules_dir):
        for f in files:
            if f.endswith(('.yaml', '.yml')):
                path = os.path.join(root, f)
                with open(path, 'r') as fh:
                    data = yaml.safe_load(fh) or {}
                    if isinstance(data, dict):
                        # Support either flat format or top-level component key (e.g., {'apiserver': {...}})
                        if len(data.keys()) == 1 and isinstance(next(iter(data.values())), dict):
                            comp, inner = next(iter(data.items()))
                            inner = dict(inner)
                            inner.setdefault('component', comp)
                            yamls.append(inner)
                        else:
                            yamls.append(data)
                    elif isinstance(data, list):
                        for d in data:
                            if isinstance(d, dict):
                                if len(d.keys()) == 1 and isinstance(next(iter(d.values())), dict):
                                    comp, inner = next(iter(d.items()))
                                    inner = dict(inner)
                                    inner.setdefault('component', comp)
                                    yamls.append(inner)
                                else:
                                    yamls.append(d)
    return yamls


def _ensure_list(obj: Any) -> List[Any]:
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    return [obj]


def _applies_matches(applies: Dict[str, Any], provider: Optional[str], managed: Optional[bool]) -> bool:
    allowed_providers = set(_ensure_list(applies.get('providers')))
    excluded_providers = set(_ensure_list(applies.get('exclude_providers')))
    managed_required = applies.get('managed_control_plane')

    if allowed_providers and provider not in allowed_providers:
        return False
    if excluded_providers and provider in excluded_providers:
        return False
    if managed_required is not None and (bool(managed) != bool(managed_required)):
        return False
    return True


def _definition_applicable(definition: Dict[str, Any], provider: Optional[str], managed: Optional[bool]) -> bool:
    """
    Determine if a definition applies.
    Priority: explicit 'applies' block > component_type defaults.
    component_type defaults:
      - 'control_plane': applies only when managed_control_plane == False
      - 'provider_control_plane': applies only when managed_control_plane == True
    """
    applies = definition.get('applies') or {}
    if applies:
        return _applies_matches(applies, provider, managed)

    comp_type = (definition.get('component_type') or '').lower()
    if comp_type == 'control_plane':
        return not bool(managed)
    if comp_type == 'provider_control_plane':
        return bool(managed)
    # default: applicable
    return True


def run_yaml_engine(
    yaml_root: str,
    kubeconfig: Optional[str] = None,
    context: Optional[str] = None,
    target_components: Optional[List[str]] = None,
    verbose: bool = False,
    discovery_dump_path: Optional[str] = None,
    mocks: Optional[Dict[str, Any]] = None,
    api_client: Optional[client.ApiClient] = None,
    v1_api: Optional[client.CoreV1Api] = None,
    inventory: Optional[Dict[str, Any]] = None,
    auto_init: bool = True,
) -> List[CheckResult]:
    start = time.time()
    results: List[CheckResult] = []

    mocks = mocks or {}

    # Initialize clients and inventory only if not provided and auto_init enabled and no mocks
    if not mocks and auto_init and (api_client is None or v1_api is None):
        try:
            api_client = load_kube_api_client(kubeconfig, context)
            v1_api = client.CoreV1Api(api_client)
        except Exception as e:
            return [CheckResult(
                check_id="yaml_engine_init_error",
                check_name="YAML Engine Initialization",
                status=CheckStatus.ERROR,
                status_extended=f"Failed to initialize Kubernetes API client: {e}",
                resource_id="kubernetes",
                resource_name="kubernetes",
                resource_type="Component",
                severity=CheckSeverity.CRITICAL,
            )]

    if inventory is None:
        inventory = {}
        if not mocks and auto_init:
            try:
                inventory = discover_kubernetes_inventory(kubeconfig=kubeconfig, context=context)
            except Exception:
                inventory = {}

    # Load YAML definitions
    definitions = _load_yaml_files(yaml_root)
    if verbose:
        print(f"Loaded {len(definitions)} YAML definition files from {yaml_root}")

    # Prepare action registry
    actions = ActionRegistry(api_client=api_client, v1_api=v1_api, inventory=inventory, mocks=mocks)

    cluster_info = (inventory or {}).get('cluster_info', {})
    provider = cluster_info.get('provider')
    managed = cluster_info.get('managed_control_plane')

    # Execute per-definition
    for definition in definitions:
        component = definition.get('component') or definition.get('service') or 'kubernetes'
        if target_components and component not in target_components:
            continue

        # Definition-level applicability using explicit applies or component_type defaults
        if not _definition_applicable(definition, provider, managed):
            if verbose:
                print(f"Skipping {component} due to applicability: provider={provider}, managed={managed}")
            continue

        # Discovery phase
        discovery_results: Dict[str, List[Any]] = {}
        for disc in _ensure_list(definition.get('discovery')):
            discovery_id = disc.get('discovery_id')
            calls: List[Dict[str, Any]] = _ensure_list(disc.get('calls'))
            aggregated: List[Any] = []

            for call in calls:
                action_name = call.get('action')
                fields = _ensure_list(call.get('fields'))
                # Execute action
                try:
                    payload = actions.execute(action_name, params=call.get('params') or {})
                except Exception as e:
                    # Record discovery error as a single result and continue to next definition
                    results.append(CheckResult(
                        check_id=f"{component}_discovery_error",
                        check_name=f"{component} Discovery Error",
                        status=CheckStatus.ERROR,
                        status_extended=f"Action {action_name} failed: {e}",
                        resource_id=component,
                        resource_name=component,
                        resource_type="Component",
                        severity=CheckSeverity.MEDIUM,
                        metadata={"action": action_name}
                    ))
                    payload = None

                # Extract requested fields into snapshots (handle list or single payload)
                if payload is not None:
                    payload_items = payload if isinstance(payload, list) else [payload]
                    for obj in payload_items:
                        snapshot: Dict[str, Any] = {}
                        for fld in fields:
                            path_expr = fld.get('path')
                            var_name = fld.get('var') or path_expr
                            snapshot[var_name] = actions.resolve_path(obj, path_expr)
                        aggregated.append(snapshot)

            if discovery_id:
                discovery_results[discovery_id] = aggregated

        # Optional dump
        if discovery_dump_path:
            try:
                # If a directory is provided, write per-component JSON files and merge by discovery_id
                if os.path.isdir(discovery_dump_path) or discovery_dump_path.endswith(os.sep):
                    os.makedirs(discovery_dump_path, exist_ok=True)
                    component_name = definition.get('component') or definition.get('service') or 'kubernetes'
                    out_file = os.path.join(discovery_dump_path, f"{component_name}_inventory.json")

                    # Merge with existing file if present
                    existing: Dict[str, List[Any]] = {}
                    if os.path.isfile(out_file):
                        try:
                            with open(out_file, 'r') as fh:
                                existing = json.load(fh) or {}
                        except Exception:
                            existing = {}

                    merged: Dict[str, List[Any]] = {}
                    # Combine lists per discovery_id
                    all_keys = set(list(existing.keys()) + list(discovery_results.keys()))
                    for key in all_keys:
                        prev = existing.get(key) or []
                        curr = discovery_results.get(key) or []
                        # Ensure list-typed values
                        prev_list = prev if isinstance(prev, list) else [prev]
                        curr_list = curr if isinstance(curr, list) else [curr]
                        merged[key] = prev_list + curr_list

                    with open(out_file, 'w') as fh:
                        json.dump(merged, fh, indent=2)
                else:
                    # Single file path provided; write JSON dump for this definition (overwrites)
                    os.makedirs(os.path.dirname(discovery_dump_path), exist_ok=True)
                    with open(discovery_dump_path, 'w') as fh:
                        json.dump(discovery_results, fh, indent=2)
            except Exception:
                pass

        # Checks phase
        for chk in _ensure_list(definition.get('checks')):
            check_id = chk.get('check_id') or "unknown_check"
            human_name = chk.get('name') or check_id.replace('_', ' ').title()
            severity_str = (chk.get('severity') or 'MEDIUM').upper()
            severity = getattr(CheckSeverity, severity_str, CheckSeverity.MEDIUM)

            for_each = chk.get('for_each')
            param_name = chk.get('param') or 'item'
            calls = _ensure_list(chk.get('calls'))
            logic = (chk.get('logic') or 'AND').upper()
            errors_as_fail = set(_ensure_list(chk.get('errors_as_fail')))
            pass_when_empty = bool(chk.get('pass_when_empty'))

            items = discovery_results.get(for_each, [{}]) if for_each else [{}]

            # Check-level applicability remains supported for mixed cases
            check_applies = chk.get('applies') or {}
            if check_applies and not _applies_matches(check_applies, provider, managed):
                for idx, _item in enumerate(items or [{}]):
                    results.append(CheckResult(
                        check_id=check_id,
                        check_name=human_name,
                        status=CheckStatus.SKIP,
                        status_extended=f"Skipped: not applicable for provider={provider}, managed={managed}",
                        resource_id=str(idx),
                        resource_name=f"{component}:{idx}",
                        resource_type="Component",
                        cluster_name=cluster_info.get('git_version'),
                        severity=severity,
                        metadata={"component": component, "index": idx, "provider": provider, "managed": managed}
                    ))
                continue

            if not items and pass_when_empty:
                results.append(CheckResult(
                    check_id=check_id,
                    check_name=human_name,
                    status=CheckStatus.PASS,
                    status_extended="No items found",
                    resource_id="N/A",
                    resource_name=f"{component}:N/A",
                    resource_type="Component",
                    cluster_name=cluster_info.get('git_version') if inventory else None,
                    severity=severity,
                    metadata={"component": component, "provider": provider, "managed": managed}
                ))
                continue

            for idx, item in enumerate(items):
                status = CheckStatus.PASS
                status_messages: List[str] = []
                metadata: Dict[str, Any] = {"component": component, "index": idx, "provider": provider, "managed": managed}
                try:
                    action_context = {param_name: item}
                    local_passes: List[bool] = []
                    for call in calls:
                        action_name = call.get('action')
                        fields = _ensure_list(call.get('fields'))
                        payload = actions.execute(action_name, params={**(call.get('params') or {}), **action_context})
                        for fld in fields:
                            path_expr = fld.get('path')
                            operator = fld.get('operator')
                            expected = fld.get('expected')
                            actual = actions.resolve_path(payload, path_expr)
                            ok = evaluate_field_condition(actual, operator, expected)
                            local_passes.append(ok)
                            if not ok:
                                status_messages.append(f"{path_expr} expected {operator} {expected}, got {actual}")

                    final_ok = all(local_passes) if logic == 'AND' else any(local_passes)
                    status = CheckStatus.PASS if final_ok else CheckStatus.FAIL
                except Exception as e:
                    status = CheckStatus.FAIL if check_id in errors_as_fail else CheckStatus.ERROR
                    status_messages.append(str(e))

                results.append(CheckResult(
                    check_id=check_id,
                    check_name=human_name,
                    status=status,
                    status_extended="; ".join(status_messages) if status_messages else ("Compliant" if status == CheckStatus.PASS else "Non-compliant"),
                    resource_id=str(idx),
                    resource_name=f"{component}:{idx}",
                    resource_type="Component",
                    cluster_name=cluster_info.get('git_version') if inventory else None,
                    severity=severity,
                    metadata=metadata
                ))

    elapsed = time.time() - start
    for r in results:
        r.execution_time = elapsed

    return results 