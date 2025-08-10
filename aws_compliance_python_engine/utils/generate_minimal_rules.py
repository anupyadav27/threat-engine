import os
import json
import yaml
from typing import List, Dict, Any

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
LEGACY_ROOT = os.path.join(ROOT, 'services')
ENGINE_SERVICES_ROOT = os.path.join(os.path.dirname(__file__), '..', 'services')
CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'service_list.json')

# Default scopes by service type (override as needed)
DEFAULT_SCOPE = {
    # Globals
    's3': 'global',
    'iam': 'global',
    'route53': 'global',
    'cloudfront': 'global',
    'organizations': 'global',
    'waf': 'global',
    'wafv2': 'global',
    'trustedadvisor': 'global',
    # Everything else default to regional
}

def list_service_dirs() -> List[str]:
    return [d for d in os.listdir(LEGACY_ROOT) if os.path.isdir(os.path.join(LEGACY_ROOT, d)) and not d.startswith('__')]


def list_check_modules(service_dir: str) -> List[str]:
    checks: List[str] = []
    full = os.path.join(LEGACY_ROOT, service_dir)
    for root, _, files in os.walk(full):
        for name in files:
            if not name.endswith('.py'):
                continue
            if name == '__init__.py':
                continue
            checks.append(os.path.join(root, name))
    return checks


def infer_check_id(py_path: str) -> str:
    base = os.path.splitext(os.path.basename(py_path))[0]
    return base


def ensure_engine_service_dir(service: str):
    target = os.path.join(ENGINE_SERVICES_ROOT, service)
    os.makedirs(target, exist_ok=True)


def load_existing_yaml(service: str) -> Dict[str, Any]:
    path = os.path.join(ENGINE_SERVICES_ROOT, service, f"{service}_rules.yaml")
    if not os.path.exists(path):
        return {service: {'scope': DEFAULT_SCOPE.get(service, 'regional'), 'discovery': [], 'checks': []}}
    with open(path, 'r') as f:
        data = yaml.safe_load(f)
    if service not in data:
        # normalize
        return {service: data}
    return data


def save_yaml(service: str, data: Dict[str, Any]):
    path = os.path.join(ENGINE_SERVICES_ROOT, service, f"{service}_rules.yaml")
    with open(path, 'w') as f:
        yaml.safe_dump(data, f, sort_keys=False)


def update_service_list(services: List[str]):
    with open(CONFIG_PATH, 'r') as f:
        cfg = json.load(f)
    existing = {s['name']: s for s in cfg.get('services', [])}
    for svc in services:
        if svc in existing:
            continue
        scope = DEFAULT_SCOPE.get(svc, 'regional')
        cfg['services'].append({"name": svc, "enabled": False, "scope": scope})
    with open(CONFIG_PATH, 'w') as f:
        json.dump(cfg, f, indent=2)


def main():
    services = list_service_dirs()
    # Ensure engine services dir exists
    os.makedirs(ENGINE_SERVICES_ROOT, exist_ok=True)
    for svc in services:
        ensure_engine_service_dir(svc)
        rules = load_existing_yaml(svc)
        block = rules[svc]
        existing_ids = {c['check_id'] for c in block.get('checks', []) if isinstance(c, dict) and 'check_id' in c}
        # enumerate checks
        for py in list_check_modules(svc):
            cid = infer_check_id(py)
            if cid in existing_ids:
                continue
            block.setdefault('checks', []).append({'check_id': cid, '_todo': 'Manual review: add for_each, param, calls'})
        rules[svc] = block
        save_yaml(svc, rules)
    update_service_list(services)
    print(f"Generated/updated minimal YAML for {len(services)} services.")


if __name__ == '__main__':
    main() 