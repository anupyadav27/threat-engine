"""
Grouping Helper

Helper functions to group compliance results by control ID and by resource.
"""

from typing import Dict, List, Any
from collections import defaultdict


def group_by_control(framework_data: Dict[str, Dict[str, List[Dict]]], framework: str) -> Dict[str, Any]:
    """
    Group results by Control ID.
    For each control, show all resources and their compliance status.
    
    Args:
        framework_data: Output from aggregate_by_framework
        framework: Framework name
    
    Returns:
        Dictionary grouped by control_id
    """
    grouped = {}
    
    if framework not in framework_data:
        return grouped
    
    for control_id, control_checks in framework_data[framework].items():
        # Get control metadata from first check
        control_meta = {}
        if control_checks:
            first_check = control_checks[0]
            control_meta = first_check.get('control', {})
        
        # Group checks by resource
        resources_by_status = defaultdict(list)
        for check in control_checks:
            resource = check.get('resource', {})
            resource_id = resource.get('id') or resource.get('arn', 'unknown')
            resource_arn = resource.get('arn', resource_id)
            
            status = check.get('check_result', 'UNKNOWN')
            resources_by_status[status].append({
                'resource_id': resource_id,
                'resource_arn': resource_arn,
                'resource_type': resource.get('type', 'unknown'),
                'region': check.get('region', 'unknown'),
                'service': check.get('service', 'unknown'),
                'rule_id': check.get('rule_id'),
                'severity': check.get('severity', 'medium'),
                'evidence': check.get('evidence', {}),
                'check_result': status
            })
        
        # Calculate control statistics
        total_resources = len(control_checks)
        passed = len(resources_by_status.get('PASS', []))
        failed = len(resources_by_status.get('FAIL', []))
        partial = len(resources_by_status.get('PARTIAL', []))
        error = len(resources_by_status.get('ERROR', []))
        
        grouped[control_id] = {
            'control_id': control_id,
            'control_title': control_meta.get('control_title', ''),
            'control_category': control_meta.get('control_category', ''),
            'framework_version': control_meta.get('framework_version', ''),
            'statistics': {
                'total_resources': total_resources,
                'passed': passed,
                'failed': failed,
                'partial': partial,
                'error': error,
                'compliance_percentage': (passed / total_resources * 100) if total_resources > 0 else 0
            },
            'resources_passed': resources_by_status.get('PASS', []),
            'resources_failed': resources_by_status.get('FAIL', []),
            'resources_partial': resources_by_status.get('PARTIAL', []),
            'resources_error': resources_by_status.get('ERROR', []),
            'all_resources': {
                'passed': resources_by_status.get('PASS', []),
                'failed': resources_by_status.get('FAIL', []),
                'partial': resources_by_status.get('PARTIAL', []),
                'error': resources_by_status.get('ERROR', [])
            }
        }
    
    return grouped


def group_by_resource(framework_data: Dict[str, Dict[str, List[Dict]]], framework: str) -> Dict[str, Any]:
    """
    Group results by Resource.
    For each resource, show all compliance controls and their status.
    
    Args:
        framework_data: Output from aggregate_by_framework
        framework: Framework name
    
    Returns:
        Dictionary grouped by resource ARN
    """
    resource_map = defaultdict(lambda: {
        'resource_info': {},
        'controls': defaultdict(list),
        'compliance_summary': {
            'total_controls': 0,
            'passed': 0,
            'failed': 0,
            'partial': 0,
            'error': 0
        }
    })
    
    if framework not in framework_data:
        return {}
    
    for control_id, control_checks in framework_data[framework].items():
        for check in control_checks:
            resource = check.get('resource', {})
            resource_id = resource.get('id') or resource.get('arn', 'unknown')
            resource_arn = resource.get('arn', resource_id)
            
            # Store resource info
            if not resource_map[resource_arn]['resource_info']:
                resource_map[resource_arn]['resource_info'] = {
                    'resource_id': resource_id,
                    'resource_arn': resource_arn,
                    'resource_type': resource.get('type', 'unknown'),
                    'region': check.get('region', 'unknown'),
                    'service': check.get('service', 'unknown'),
                    'account_id': check.get('account_id', 'unknown')
                }
            
            # Get control metadata
            control_meta = check.get('control', {})
            
            # Add control check to resource
            control_entry = {
                'control_id': control_id,
                'control_title': control_meta.get('control_title', ''),
                'control_category': control_meta.get('control_category', ''),
                'rule_id': check.get('rule_id'),
                'check_result': check.get('check_result', 'UNKNOWN'),
                'severity': check.get('severity', 'medium'),
                'evidence': check.get('evidence', {}),
                'framework_version': control_meta.get('framework_version', '')
            }
            
            resource_map[resource_arn]['controls'][control_id].append(control_entry)
            
            # Update summary
            status = check.get('check_result', 'UNKNOWN')
            resource_map[resource_arn]['compliance_summary']['total_controls'] += 1
            if status == 'PASS':
                resource_map[resource_arn]['compliance_summary']['passed'] += 1
            elif status == 'FAIL':
                resource_map[resource_arn]['compliance_summary']['failed'] += 1
            elif status == 'PARTIAL':
                resource_map[resource_arn]['compliance_summary']['partial'] += 1
            elif status == 'ERROR':
                resource_map[resource_arn]['compliance_summary']['error'] += 1
    
    # Convert to final format
    result = {}
    for resource_arn, data in resource_map.items():
        # Calculate compliance score
        summary = data['compliance_summary']
        total = summary['total_controls']
        passed = summary['passed']
        compliance_score = (passed / total * 100) if total > 0 else 0
        
        # Convert controls dict to list
        controls_list = []
        for control_id, checks in data['controls'].items():
            # Determine control status (if any check fails, control fails)
            has_fail = any(c['check_result'] == 'FAIL' for c in checks)
            has_pass = any(c['check_result'] == 'PASS' for c in checks)
            
            if has_fail and has_pass:
                control_status = 'PARTIAL'
            elif has_fail:
                control_status = 'FAIL'
            elif has_pass:
                control_status = 'PASS'
            else:
                control_status = 'UNKNOWN'
            
            controls_list.append({
                'control_id': control_id,
                'control_title': checks[0].get('control_title', ''),
                'control_category': checks[0].get('control_category', ''),
                'status': control_status,
                'checks': checks
            })
        
        result[resource_arn] = {
            'resource_info': data['resource_info'],
            'compliance_score': round(compliance_score, 2),
            'compliance_summary': summary,
            'controls': controls_list,
            'failed_controls': [c for c in controls_list if c['status'] == 'FAIL'],
            'passed_controls': [c for c in controls_list if c['status'] == 'PASS'],
            'partial_controls': [c for c in controls_list if c['status'] == 'PARTIAL']
        }
    
    return result
