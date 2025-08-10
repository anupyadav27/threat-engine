import os
import re
import sys
import yaml
from typing import Dict, List, Any

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
LEGACY_ROOT = os.path.join(ROOT, 'services')
ENGINE_SERVICES_ROOT = os.path.join(os.path.dirname(__file__), '..', 'services')

# Mapping heuristics per service
S3_ACTION_MAP = {
    # key: substring to match in check_id or filename → tuple(action, path list [ (path, operator, expected) ], multi_step, logic)
    'default_encryption': ('get_bucket_encryption', [
        ('ServerSideEncryptionConfiguration.Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm', 'exists', None)
    ], False, 'AND'),
    'kms_encryption': ('get_bucket_encryption', [
        ('ServerSideEncryptionConfiguration.Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm', 'equals', 'aws:kms')
    ], False, 'AND'),
    'object_versioning': ('get_bucket_versioning', [
        ('Status', 'equals', 'Enabled')
    ], False, 'AND'),
    'mfa_delete': ('get_bucket_versioning', [
        ('MFADelete', 'equals', 'Enabled')
    ], False, 'AND'),
    'server_access_logging_enabled': ('get_bucket_logging', [
        ('LoggingEnabled.TargetBucket', 'exists', None)
    ], False, 'AND'),
    'lifecycle_enabled': ('get_bucket_lifecycle_configuration', [
        ('Rules[]', 'exists', None)
    ], False, 'AND'),
    'replication': ('get_bucket_replication', [
        ('ReplicationConfiguration.Rules[]', 'exists', None)
    ], False, 'AND'),
    'object_lock': ('get_object_lock_configuration', [
        ('ObjectLockConfiguration.ObjectLockEnabled', 'equals', 'Enabled')
    ], False, 'AND'),
    'event_notifications_enabled': ('get_bucket_notification_configuration', [
        ('QueueConfigurations[]', 'exists', None),
        ('TopicConfigurations[]', 'exists', None),
        ('LambdaFunctionConfigurations[]', 'exists', None)
    ], True, 'OR'),
    'public_write_acl': ('get_bucket_acl', [
        ('Grants[].Grantee.URI', 'contains', 'AllUsers'),
        ('Grants[].Permission', 'contains', 'WRITE')
    ], True, 'AND'),
    'public_list_acl': ('get_bucket_acl', [
        ('Grants[].Grantee.URI', 'contains', 'AllUsers'),
        ('Grants[].Permission', 'contains', 'READ')
    ], True, 'AND'),
    'public_access': None,  # covered by existing composite check in YAML
    'policy_public_write_access': ('get_bucket_policy', [
        ('Statement[].Principal', 'equals', '*'),
        ('Statement[].Action', 'contains', 's3:PutObject')
    ], True, 'AND'),
    # Stubs to review manually
    'secure_transport_policy': 'TODO',
    'acl_prohibited': 'TODO',
    'cross_account_access': 'TODO',
}

SERVICE_CONFIG = {
    's3': {
        'resource_for_each': 'list_buckets',
        'param': 'Bucket',
        'action_map': S3_ACTION_MAP,
        'legacy_skip_files': {'s3_service.py', 's3_client.py', 's3control_client.py', '__init__.py'},
    }
}


def load_yaml_rules(service: str) -> Dict[str, Any]:
    path = os.path.join(ENGINE_SERVICES_ROOT, service, f"{service}_rules.yaml")
    with open(path, 'r') as f:
        data = yaml.safe_load(f)
    return data


def save_yaml_rules(service: str, data: Dict[str, Any]):
    path = os.path.join(ENGINE_SERVICES_ROOT, service, f"{service}_rules.yaml")
    with open(path, 'w') as f:
        yaml.safe_dump(data, f, sort_keys=False)


def list_legacy_checks(service: str) -> List[str]:
    service_dir = os.path.join(LEGACY_ROOT, service)
    py_files: List[str] = []
    for root, _, files in os.walk(service_dir):
        for name in files:
            if name.endswith('.py') and name not in SERVICE_CONFIG[service]['legacy_skip_files']:
                py_files.append(os.path.join(root, name))
    return py_files


def infer_check_id(py_path: str) -> str:
    base = os.path.splitext(os.path.basename(py_path))[0]
    return base


def contains_get_all_buckets(py_path: str) -> bool:
    try:
        with open(py_path, 'r') as f:
            txt = f.read()
        return 'get_all_buckets(' in txt
    except Exception:
        return False


def build_check_entry_s3(check_id: str) -> Dict[str, Any]:
    mapping = SERVICE_CONFIG['s3']['action_map']
    # resolve key by substring
    resolved = None
    for key, spec in mapping.items():
        if key and key != 'TODO' and key in check_id:
            resolved = spec
            break
    entry: Dict[str, Any] = {
        'check_id': check_id,
        'for_each': SERVICE_CONFIG['s3']['resource_for_each'],
        'param': SERVICE_CONFIG['s3']['param'],
        'calls': []
    }
    if resolved == 'TODO' or resolved is None:
        entry['calls'].append({
            'action': 'TODO_ACTION',
            'fields': [
                {'path': 'TODO_PATH', 'operator': 'TODO_OPERATOR', 'expected': 'TODO_EXPECTED'}
            ]
        })
        entry['multi_step'] = False
        entry['logic'] = 'AND'
        entry['_todo'] = f"Manual review required for {check_id}"
        return entry
    action, fields, multi_step, logic = resolved
    entry['calls'].append({
        'action': action,
        'fields': [
            {'path': p, **({'operator': op} if op else {}), **({'expected': exp} if exp is not None else {})}
            for (p, op, exp) in fields
        ]
    })
    if multi_step:
        entry['multi_step'] = True
        entry['logic'] = logic
    return entry


def update_rules_for_service(service: str) -> int:
    rules = load_yaml_rules(service)
    existing_checks = {c['check_id'] for c in rules.get(service, rules).get('checks', [])} if service not in rules else {c['check_id'] for c in rules[service].get('checks', [])}
    # normalize structure where top-level is service
    service_block = rules if 'discovery' in rules else rules[service]

    added = 0
    for py in list_legacy_checks(service):
        check_id = infer_check_id(py)
        if check_id in existing_checks:
            continue
        # Only handle S3 for now
        if service == 's3':
            if not contains_get_all_buckets(py):
                # likely not bucket-scoped or requires manual
                entry = build_check_entry_s3(check_id)
            else:
                entry = build_check_entry_s3(check_id)
        else:
            continue
        service_block.setdefault('checks', []).append(entry)
        added += 1
    # Save back
    if 'discovery' in rules:
        save_yaml_rules(service, rules)
    else:
        save_yaml_rules(service, {service: service_block})
    return added


def main():
    if len(sys.argv) < 2:
        print('Usage: python generate_rules_from_checks.py <service>')
        sys.exit(1)
    service = sys.argv[1]
    if service not in SERVICE_CONFIG:
        print(f'Service {service} not supported')
        sys.exit(2)
    added = update_rules_for_service(service)
    print(f'Added {added} check stubs for {service}')


if __name__ == '__main__':
    main() 