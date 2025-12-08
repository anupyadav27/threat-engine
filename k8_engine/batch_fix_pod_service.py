#!/usr/bin/env python3
"""Batch fix remaining placeholder checks in pod service"""
import yaml
from pathlib import Path

def fix_pod_placeholders():
    """Fix remaining pod service placeholder checks"""
    
    pod_file = Path(__file__).parent / "services/pod/pod_rules.yaml"
    
    with open(pod_file, 'r') as f:
        data = yaml.safe_load(f)
    
    # Define mappings for common placeholder patterns
    fix_mappings = {
        # Name-based placeholders that should check actual pod fields
        "item.name": {
            "container.horizontal_autoscaler_enabled": "item.annotations.autoscaling",
            "container.sbom_management_enabled": "item.annotations.sbom",
            "container.security_context_memory_protection_enabled": "item.containers[0].securityContext.runAsNonRoot",
            "deployment.anomaly_detection_enabled": "item.annotations.monitoring",
            "pod.annotation_standard_configured": "item.annotations",
            "pod.annotations_for_inventory_metadata_configured": "item.annotations",
            "pod.annotations_maintained": "item.annotations",
            "pod.disruption_budget_configured": "item.annotations.pdb",
            "pod.ebpf_monitoring_enabled": "item.annotations.ebpf",
            "pod.falco_enabled_enforced": "item.annotations.falco",
            "pod.inventory_labels_maintained": "item.labels",
            "pod.labeling_standard_configured": "item.labels",
            "pod.patch_management_enabled": "item.annotations.patch",
            "pod.termination_grace_period_configured": "item.annotations.gracePeriod",
            "securitycontext.non_root": "item.containers[0].securityContext.runAsNonRoot",
            "securitycontext.readonly_rootfs": "item.containers[0].securityContext.readOnlyRootFilesystem"
        }
    }
    
    # Apply fixes
    fixes_applied = 0
    checks = data.get('checks', [])
    
    for check in checks:
        check_id = check.get('check_id', '')
        calls = check.get('calls', [])
        
        for call in calls:
            fields = call.get('fields', [])
            for field in fields:
                path = field.get('path', '')
                
                if path == 'item.name':
                    # Find matching pattern in check_id
                    for pattern, new_path in fix_mappings["item.name"].items():
                        if pattern in check_id:
                            field['path'] = new_path
                            # Adjust operator based on new path
                            if 'annotations' in new_path or 'labels' in new_path:
                                field['operator'] = 'exists'
                                field['expected'] = None
                            elif 'securityContext' in new_path:
                                if 'non_root' in check_id or 'readonly' in check_id:
                                    field['operator'] = 'equals'
                                    field['expected'] = True
                                else:
                                    field['operator'] = 'exists'
                                    field['expected'] = None
                            fixes_applied += 1
                            print(f"Fixed {check_id}: {path} -> {new_path}")
                            break
    
    # Write back the fixed file
    with open(pod_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    print(f"\nApplied {fixes_applied} fixes to pod service")
    return fixes_applied

if __name__ == '__main__':
    fix_pod_placeholders()
