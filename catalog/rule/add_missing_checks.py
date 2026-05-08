#!/usr/bin/env python3
"""
Script to add 28 missing Azure check YAML entries for rules that exist in the
catalog metadata but have no corresponding check entries.

Services affected:
- backup (4 rules)
- compute (22 rules)
- data_factory (2 rules)
"""

import yaml
import os

BASE_DIR = "/Users/apple/Desktop/threat-engine/catalog/rule/azure_rule_check"


def read_yaml(filepath):
    """Read a YAML file and return parsed content."""
    with open(filepath, "r") as f:
        return yaml.safe_load(f)


def write_yaml(filepath, data):
    """Write data to a YAML file preserving formatting."""
    with open(filepath, "w") as f:
        yaml.dump(
            data,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=200,
        )


def get_backup_new_checks():
    """Return the 4 new backup vault check entries."""
    return [
        {
            "rule_id": "azure.backup.backup_vault.encryption_cmk_cmek_key_configured",
            "conditions": {
                "all": [
                    {
                        "var": "item.encryption.key_vault_properties.key_uri",
                        "op": "not_empty",
                    },
                    {
                        "var": "item.encryption.infrastructure_encryption",
                        "op": "equals",
                        "value": "Enabled",
                    },
                ]
            },
        },
        {
            "rule_id": "azure.backup.backup_vault.encryption_encryption_at_rest_enabled",
            "conditions": {
                "all": [
                    {
                        "var": "item.security_settings.encryption_settings.state",
                        "op": "equals",
                        "value": "Enabled",
                    },
                    {
                        "var": "item.security_settings.encryption_settings.infrastructure_encryption",
                        "op": "equals",
                        "value": "Enabled",
                    },
                ]
            },
        },
        {
            "rule_id": "azure.backup.backup_vault.encryption_encryption_in_transit_tls_min_1_2",
            "conditions": {
                "var": "item.security_settings.encryption_settings.min_tls_version",
                "op": "equals",
                "value": "1.2",
            },
        },
        {
            "rule_id": "azure.backup.backup_vault.encryption_key_rotation_enabled",
            "conditions": {
                "all": [
                    {
                        "var": "item.encryption.key_vault_properties.key_uri",
                        "op": "not_empty",
                    },
                    {
                        "var": "item.security_settings.encryption_settings.infrastructure_encryption",
                        "op": "equals",
                        "value": "Enabled",
                    },
                ]
            },
        },
    ]


def get_compute_new_checks():
    """Return the 22 new compute check entries."""
    return [
        # --- Disk ---
        {
            "rule_id": "azure.compute.disk.disk_cmk_cmek_configured",
            "for_each": "azure.compute.disks.list_by_resource_group",
            "conditions": {
                "var": "item.encryption.disk_encryption_set_id",
                "op": "not_empty",
            },
        },
        # --- Image ---
        {
            "rule_id": "azure.compute.image.image_approved_image_allowlist_enforced",
            "conditions": {
                "var": "item.source_virtual_machine.id",
                "op": "not_empty",
            },
        },
        # --- Spot Virtual Machine ---
        {
            "rule_id": "azure.compute.spot_virtual_machine.spot_instance_instance_profile_least_privilege",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "all": [
                    {
                        "var": "item.priority",
                        "op": "equals",
                        "value": "Spot",
                    },
                    {
                        "var": "item.identity.type",
                        "op": "not_empty",
                    },
                ]
            },
        },
        {
            "rule_id": "azure.compute.spot_virtual_machine.spot_instance_no_public_ip_assigned",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "all": [
                    {
                        "var": "item.priority",
                        "op": "equals",
                        "value": "Spot",
                    },
                    {
                        "var": "item.network_profile.network_interfaces",
                        "op": "not_empty",
                    },
                ]
            },
        },
        {
            "rule_id": "azure.compute.spot_virtual_machine.spot_instance_uses_approved_launch_template",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "all": [
                    {
                        "var": "item.priority",
                        "op": "equals",
                        "value": "Spot",
                    },
                    {
                        "var": "item.storage_profile.image_reference.id",
                        "op": "not_empty",
                    },
                ]
            },
        },
        # --- Virtual Machine ---
        {
            "rule_id": "azure.compute.virtual_machine.vm_data_volumes_encrypted_cmek",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "all": [
                    {
                        "var": "item.storage_profile.data_disks[*].managed_disk.disk_encryption_set.id",
                        "op": "not_empty",
                    },
                    {
                        "var": "item.storage_profile.data_disks[*].managed_disk.id",
                        "op": "not_empty",
                    },
                ]
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine.vm_imds_hardened",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "var": "item.security_profile.encryption_at_host",
                "op": "equals",
                "value": "true",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine.vm_no_public_ip_assigned",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "var": "item.network_profile.network_interfaces",
                "op": "not_empty",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine.vm_root_volume_encrypted_cmek",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "var": "item.storage_profile.os_disk.managed_disk.disk_encryption_set.id",
                "op": "not_empty",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine.vm_secure_boot_enabled",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "var": "item.security_profile.uefi_settings.secure_boot_enabled",
                "op": "equals",
                "value": "true",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine.vm_security_group_inbound_restricted",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "var": "item.network_profile.network_interfaces",
                "op": "not_empty",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine.vm_serial_console_access_restricted",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "var": "item.diagnostics_profile.boot_diagnostics.enabled",
                "op": "equals",
                "value": "true",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine.vm_ssh_key_based_auth_required",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "all": [
                    {
                        "var": "item.os_profile.linux_configuration.disable_password_authentication",
                        "op": "equals",
                        "value": "true",
                    },
                    {
                        "var": "item.os_profile.linux_configuration.ssh.public_keys",
                        "op": "not_empty",
                    },
                ]
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine.vm_ssh_password_auth_disabled",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "var": "item.os_profile.linux_configuration.disable_password_authentication",
                "op": "equals",
                "value": "true",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine.vm_user_data_no_secrets",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "var": "item.user_data",
                "op": "not_contains",
                "value": "password",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine.vm_vtpm_enabled",
            "for_each": "azure.compute.virtualmachines.list_all",
            "conditions": {
                "var": "item.security_profile.uefi_settings.v_tpm_enabled",
                "op": "equals",
                "value": "true",
            },
        },
        # --- Virtual Machine Template (VMSS-based) ---
        {
            "rule_id": "azure.compute.virtual_machine_template.launch_template_imds_hardened",
            "for_each": "azure.compute.virtualmachinescalesets.list_all",
            "conditions": {
                "var": "item.virtual_machine_profile.security_profile.encryption_at_host",
                "op": "equals",
                "value": "true",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine_template.launch_template_instance_profile_least_privilege",
            "for_each": "azure.compute.virtualmachinescalesets.list_all",
            "conditions": {
                "var": "item.identity.type",
                "op": "not_empty",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine_template.launch_template_no_public_ip_default",
            "for_each": "azure.compute.virtualmachinescalesets.list_all",
            "conditions": {
                "var": "item.virtual_machine_profile.network_profile.network_interface_configurations",
                "op": "not_empty",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine_template.launch_template_root_volume_encrypted_by_default",
            "for_each": "azure.compute.virtualmachinescalesets.list_all",
            "conditions": {
                "var": "item.virtual_machine_profile.storage_profile.os_disk.managed_disk.disk_encryption_set.id",
                "op": "not_empty",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine_template.launch_template_security_groups_restrictive",
            "for_each": "azure.compute.virtualmachinescalesets.list_all",
            "conditions": {
                "var": "item.virtual_machine_profile.network_profile.network_interface_configurations",
                "op": "not_empty",
            },
        },
        {
            "rule_id": "azure.compute.virtual_machine_template.launch_template_user_data_no_secrets",
            "for_each": "azure.compute.virtualmachinescalesets.list_all",
            "conditions": {
                "var": "item.virtual_machine_profile.user_data",
                "op": "not_contains",
                "value": "password",
            },
        },
    ]


def get_data_factory_new_checks():
    """Return the 2 new data factory check entries."""
    return [
        {
            "rule_id": "azure.data_factory.pipeline_parameter.parameter_metadata_sensitive_keys_require_secret_type",
            "conditions": {
                "all": [
                    {
                        "var": "item.type_properties.connection_string",
                        "op": "exists",
                    },
                    {
                        "var": "item.type_properties.connection_string",
                        "op": "contains",
                        "value": "AccountKey=",
                    },
                    {
                        "var": "item.type_properties.connection_string",
                        "op": "contains",
                        "value": "Password=",
                    },
                    {
                        "var": "item.sql_server.type_properties.password.type",
                        "op": "equals",
                        "value": "SecureString",
                    },
                    {
                        "var": "item.azure_sql_d_w.type_properties.service_principal_key.type",
                        "op": "equals",
                        "value": "SecureString",
                    },
                    {
                        "var": "item.azure_storage.type_properties.account_key",
                        "op": "exists",
                    },
                    {
                        "var": "item.azure_storage.type_properties.sas_uri",
                        "op": "exists",
                    },
                    {
                        "var": "item.hubspot.type_properties.access_token",
                        "op": "exists",
                    },
                    {
                        "var": "item.type_properties.encrypted_credential",
                        "op": "exists",
                    },
                    {
                        "var": "item.azure_blob_storage.type_properties.credential.type",
                        "op": "exists",
                    },
                    {
                        "var": "item.azure_blob_f_s.type_properties.service_principal_credential",
                        "op": "exists",
                    },
                ]
            },
        },
        {
            "rule_id": "azure.data_factory.pipeline_parameter.parameter_type_set",
            "conditions": {
                "all": [
                    {
                        "var": "item.repo_configuration.repository_name",
                        "op": "not_empty",
                    },
                    {
                        "var": "item.repo_configuration.repository_name",
                        "op": "equals",
                    },
                ]
            },
        },
    ]


def add_checks_to_file(filepath, new_checks):
    """Read a check file, append new checks, and write back."""
    data = read_yaml(filepath)

    # Verify we have the expected structure
    assert "checks" in data, f"No 'checks' key found in {filepath}"
    assert isinstance(data["checks"], list), f"'checks' is not a list in {filepath}"

    existing_rule_ids = {c["rule_id"] for c in data["checks"]}
    added = 0

    for check in new_checks:
        if check["rule_id"] not in existing_rule_ids:
            data["checks"].append(check)
            added += 1
            print(f"  Added: {check['rule_id']}")
        else:
            print(f"  Skipped (already exists): {check['rule_id']}")

    if added > 0:
        write_yaml(filepath, data)
        print(f"  => Wrote {added} new check(s) to {filepath}")
    else:
        print(f"  => No new checks to add to {filepath}")

    return added


def main():
    total_added = 0

    # 1. Backup checks
    print("\n=== BACKUP ===")
    backup_path = os.path.join(BASE_DIR, "backup", "backup.checks.yaml")
    total_added += add_checks_to_file(backup_path, get_backup_new_checks())

    # 2. Compute checks
    print("\n=== COMPUTE ===")
    compute_path = os.path.join(BASE_DIR, "compute", "compute.checks.yaml")
    total_added += add_checks_to_file(compute_path, get_compute_new_checks())

    # 3. Data Factory checks
    print("\n=== DATA_FACTORY ===")
    df_path = os.path.join(BASE_DIR, "data_factory", "data_factory.checks.yaml")
    total_added += add_checks_to_file(df_path, get_data_factory_new_checks())

    print(f"\n=== TOTAL: {total_added} check entries added across 3 files ===")


if __name__ == "__main__":
    main()
