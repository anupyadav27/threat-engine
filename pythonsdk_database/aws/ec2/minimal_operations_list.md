# EC2 - Minimal Operations List

**Generated:** 2026-01-20T19:31:01.778756

**Total Fields:** 1201
**Total Operations Needed:** 217
**Independent Operations:** 162
**Dependent Operations:** 55
**Coverage:** 83.5%

---

## ✅ Independent Operations (Root Operations)

These operations can be called without any dependencies:

### 1. DescribeImages

- **Type:** Independent (Root)
- **Entities Covered:** 37
- **Covers:** ec2.address_tags, ec2.address_transfer_public_ip, ec2.client_vpn_endpoint_description, ec2.export_image_task_image_id, ec2.fpga_imag_name...

### 2. DescribeInstanceTypes

- **Type:** Independent (Root)
- **Entities Covered:** 30
- **Covers:** ec2.capacity_block_extension_instance_type, ec2.fpga_imag_instance_types, ec2.instance_typ_auto_recovery_supported, ec2.instance_typ_bare_metal, ec2.instance_typ_burstable_performance_supported...

### 3. DescribeNetworkInterfaces

- **Type:** Independent (Root)
- **Entities Covered:** 29
- **Covers:** ec2.address_private_ip_address, ec2.capacity_block_extension_availability_zone, ec2.capacity_block_extension_availability_zone_id, ec2.capacity_reservation_outpost_arn, ec2.carrier_gateway_vpc_id...

### 4. DescribeCapacityReservations

- **Type:** Independent (Root)
- **Entities Covered:** 25
- **Covers:** ec2.capacity_block_create_date, ec2.capacity_block_end_date, ec2.capacity_block_extension_capacity_reservation_id, ec2.capacity_block_start_date, ec2.capacity_block_status_capacity_block_id...

### 5. DescribeClientVpnEndpoints

- **Type:** Independent (Root)
- **Entities Covered:** 24
- **Covers:** ec2.certificate_arn, ec2.client_vpn_endpoint_associated_target_networks, ec2.client_vpn_endpoint_authentication_options, ec2.client_vpn_endpoint_client_cidr_block, ec2.client_vpn_endpoint_client_connect_options...

### 6. DescribeVpcEndpoints

- **Type:** Independent (Root)
- **Entities Covered:** 18
- **Covers:** ec2.connection_notification_set_service_region, ec2.instance_connect_endpoint_ip_address_type, ec2.instance_connect_endpoint_network_interface_ids, ec2.route_server_endpoint_failure_reason, ec2.service_configuration_service_name...

### 7. DescribeIpamPools

- **Type:** Independent (Root)
- **Entities Covered:** 20
- **Covers:** ec2.instance_connect_endpoint_state_message, ec2.ipam_external_resource_verification_token_ipam_arn, ec2.ipam_external_resource_verification_token_ipam_region, ec2.ipam_pool_address_family, ec2.ipam_pool_allocation_default_netmask_length...

### 8. DescribeSnapshots

- **Type:** Independent (Root)
- **Entities Covered:** 17
- **Covers:** ec2.bundle_task_progress, ec2.bundle_task_start_time, ec2.fast_snapshot_restor_owner_alias, ec2.fast_snapshot_restor_snapshot_id, ec2.import_image_task_encrypted...

### 9. DescribeVolumes

- **Type:** Independent (Root)
- **Entities Covered:** 11
- **Covers:** ec2.capacity_manager_data_export_create_time, ec2.egress_only_internet_gateway_attachments, ec2.volum_fast_restored, ec2.volum_iops, ec2.volum_multi_attach_enabled...

### 10. DescribeFleets

- **Type:** Independent (Root)
- **Entities Covered:** 19
- **Covers:** ec2.fleet_activity_status, ec2.fleet_client_token, ec2.fleet_context, ec2.fleet_errors, ec2.fleet_excess_capacity_termination_policy...

### 11. DescribeVerifiedAccessEndpoints

- **Type:** Independent (Root)
- **Entities Covered:** 15
- **Covers:** ec2.instanc_last_updated_time, ec2.verified_access_endpoint_application_domain, ec2.verified_access_endpoint_attachment_type, ec2.verified_access_endpoint_cidr_options, ec2.verified_access_endpoint_device_validation_domain...

### 12. DescribeSubnets

- **Type:** Independent (Root)
- **Entities Covered:** 14
- **Covers:** ec2.address_customer_owned_ipv4_pool, ec2.subnet_assign_ipv6_address_on_creation, ec2.subnet_available_ip_address_count, ec2.subnet_block_public_access_states, ec2.subnet_cidr_block...

### 13. DescribeHosts

- **Type:** Independent (Root)
- **Entities Covered:** 13
- **Covers:** ec2.host_allocation_time, ec2.host_allows_multiple_instance_types, ec2.host_asset_id, ec2.host_auto_placement, ec2.host_available_capacity...

### 14. DescribeReservedInstances

- **Type:** Independent (Root)
- **Entities Covered:** 15
- **Covers:** ec2.capacity_block_extension_currency_code, ec2.capacity_block_extension_instance_count, ec2.host_reservation_set_end, ec2.host_reservation_set_start, ec2.offering_set_duration...

### 15. DescribeVpcEndpointServiceConfigurations

- **Type:** Independent (Root)
- **Entities Covered:** 15
- **Covers:** ec2.connection_notification_set_service_id, ec2.service_configuration_acceptance_required, ec2.service_configuration_availability_zone_ids, ec2.service_configuration_availability_zones, ec2.service_configuration_base_endpoint_dns_names...

### 16. DescribeImportImageTasks

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.conversion_task_status_message, ec2.import_image_task_architecture, ec2.import_image_task_import_task_id, ec2.import_image_task_license_specifications, ec2.import_image_task_license_type...

### 17. DescribeSpotInstanceRequests

- **Type:** Independent (Root)
- **Entities Covered:** 12
- **Covers:** ec2.address_instance_id, ec2.spot_datafeed_subscription_fault, ec2.spot_instance_request_actual_block_hourly_price, ec2.spot_instance_request_availability_zone_group, ec2.spot_instance_request_block_duration_minutes...

### 18. DescribeVolumesModifications

- **Type:** Independent (Root)
- **Entities Covered:** 13
- **Covers:** ec2.report_end_time, ec2.volumes_modification_end_time, ec2.volumes_modification_modification_state, ec2.volumes_modification_original_iops, ec2.volumes_modification_original_multi_attach_enabled...

### 19. DescribeIpams

- **Type:** Independent (Root)
- **Entities Covered:** 12
- **Covers:** ec2.byoasn_ipam_id, ec2.ipam_default_resource_discovery_association_id, ec2.ipam_default_resource_discovery_id, ec2.ipam_enable_private_gua, ec2.ipam_metered_account...

### 20. DescribeReservedInstancesOfferings

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.reserved_instances_offering_availability_zone, ec2.reserved_instances_offering_marketplace, ec2.reserved_instances_offering_pricing_details, ec2.reserved_instances_offering_reserved_instances_offering_id

### 21. DescribeNetworkInsightsAnalyses

- **Type:** Independent (Root)
- **Entities Covered:** 13
- **Covers:** ec2.network_insights_access_scope_analys_warning_message, ec2.network_insights_analys_additional_accounts, ec2.network_insights_analys_alternate_path_hints, ec2.network_insights_analys_explanations, ec2.network_insights_analys_filter_in_arns...

### 22. DescribeNatGateways

- **Type:** Independent (Root)
- **Entities Covered:** 13
- **Covers:** ec2.nat_gateway_addresses, ec2.nat_gateway_attached_appliances, ec2.nat_gateway_auto_provision_zones, ec2.nat_gateway_auto_scaling_ips, ec2.nat_gateway_availability_mode...

### 23. DescribeScheduledInstances

- **Type:** Independent (Root)
- **Entities Covered:** 11
- **Covers:** ec2.offering_set_hourly_price, ec2.scheduled_instance_set, ec2.scheduled_instance_set_network_platform, ec2.scheduled_instance_set_next_slot_start_time, ec2.scheduled_instance_set_previous_slot_end_time...

### 24. DescribeFlowLogs

- **Type:** Independent (Root)
- **Entities Covered:** 14
- **Covers:** ec2.flow_log_creation_time, ec2.flow_log_deliver_cross_account_role, ec2.flow_log_deliver_logs_error_message, ec2.flow_log_deliver_logs_permission_arn, ec2.flow_log_deliver_logs_status...

### 25. DescribeInstanceConnectEndpoints

- **Type:** Independent (Root)
- **Entities Covered:** 7
- **Covers:** ec2.instance_connect_endpoint_arn, ec2.instance_connect_endpoint_created_at, ec2.instance_connect_endpoint_fips_dns_name, ec2.instance_connect_endpoint_instance_connect_endpoint_arn, ec2.instance_connect_endpoint_instance_connect_endpoint_id...

### 26. DescribeFpgaImages

- **Type:** Independent (Root)
- **Entities Covered:** 7
- **Covers:** ec2.bundle_task_update_time, ec2.fpga_imag_create_time, ec2.fpga_imag_data_retention_support, ec2.fpga_imag_fpga_image_global_id, ec2.fpga_imag_fpga_image_id...

### 27. ListVolumesInRecycleBin

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.imag_recycle_bin_enter_time, ec2.imag_recycle_bin_exit_time

### 28. DescribeNetworkInsightsPaths

- **Type:** Independent (Root)
- **Entities Covered:** 13
- **Covers:** ec2.network_insights_access_scop_created_date, ec2.network_insights_path_arn, ec2.network_insights_path_destination_arn, ec2.network_insights_path_destination_ip, ec2.network_insights_path_destination_port...

### 29. DescribeVerifiedAccessTrustProviders

- **Type:** Independent (Root)
- **Entities Covered:** 9
- **Covers:** ec2.verified_access_instanc_verified_access_trust_providers, ec2.verified_access_trust_provider_device_options, ec2.verified_access_trust_provider_device_trust_provider_type, ec2.verified_access_trust_provider_native_application_oidc_options, ec2.verified_access_trust_provider_oidc_options...

### 30. DescribeVpnConnections

- **Type:** Independent (Root)
- **Entities Covered:** 14
- **Covers:** ec2.customer_gateway_customer_gateway_id, ec2.route_tabl_routes, ec2.transit_gateway_attachment_transit_gateway_id, ec2.transit_gateway_connect_options, ec2.vpn_concentrator_vpn_concentrator_id...

### 31. DescribeAddresses

- **Type:** Independent (Root)
- **Entities Covered:** 10
- **Covers:** ec2.address_association_id, ec2.address_carrier_ip, ec2.address_customer_owned_ip, ec2.address_domain, ec2.address_network_border_group...

### 32. DescribeHostReservations

- **Type:** Independent (Root)
- **Entities Covered:** 7
- **Covers:** ec2.host_reservation_set, ec2.host_reservation_set_count, ec2.host_reservation_set_host_id_set, ec2.offering_set_instance_family, ec2.offering_set_offering_id...

### 33. DescribeCapacityBlockExtensionHistory

- **Type:** Independent (Root)
- **Entities Covered:** 7
- **Covers:** ec2.capacity_block_extension_capacity_block_extension_duration_hours, ec2.capacity_block_extension_capacity_block_extension_end_date, ec2.capacity_block_extension_capacity_block_extension_offering_id, ec2.capacity_block_extension_capacity_block_extension_purchase_date, ec2.capacity_block_extension_capacity_block_extension_start_date...

### 34. DescribeLocalGatewayVirtualInterfaces

- **Type:** Independent (Root)
- **Entities Covered:** 12
- **Covers:** ec2.local_gateway_route_table_virtual_interface_group_association_local_gateway_id, ec2.local_gateway_virtual_interfac_configuration_state, ec2.local_gateway_virtual_interfac_local_address, ec2.local_gateway_virtual_interfac_local_gateway_virtual_interface_arn, ec2.local_gateway_virtual_interfac_local_gateway_virtual_interface_id...

### 35. DescribeSecurityGroupRules

- **Type:** Independent (Root)
- **Entities Covered:** 11
- **Covers:** ec2.placement_group_group_id, ec2.security_group_rul_cidr_ipv4, ec2.security_group_rul_cidr_ipv6, ec2.security_group_rul_from_port, ec2.security_group_rul_group_owner_id...

### 36. DescribeVpcEndpointConnections

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.vpc_endpoint_connection_creation_timestamp, ec2.vpc_endpoint_connection_vpc_endpoint_connection_id, ec2.vpc_endpoint_connection_vpc_endpoint_owner, ec2.vpc_endpoint_connection_vpc_endpoint_region, ec2.vpc_endpoint_connection_vpc_endpoint_state

### 37. DescribeRouteServerPeers

- **Type:** Independent (Root)
- **Entities Covered:** 8
- **Covers:** ec2.route_server_endpoint_route_server_endpoint_id, ec2.route_server_endpoint_route_server_id, ec2.route_server_peer_bfd_status, ec2.route_server_peer_bgp_options, ec2.route_server_peer_bgp_status...

### 38. DescribeVpcEndpointAssociations

- **Type:** Independent (Root)
- **Entities Covered:** 7
- **Covers:** ec2.vpc_endpoint_association_associated_resource_accessibility, ec2.vpc_endpoint_association_associated_resource_arn, ec2.vpc_endpoint_association_dns_entry, ec2.vpc_endpoint_association_id, ec2.vpc_endpoint_association_private_dns_entry...

### 39. DescribeTrafficMirrorFilterRules

- **Type:** Independent (Root)
- **Entities Covered:** 9
- **Covers:** ec2.traffic_mirror_filter_id, ec2.traffic_mirror_filter_rul_destination_port_range, ec2.traffic_mirror_filter_rul_rule_action, ec2.traffic_mirror_filter_rul_rule_number, ec2.traffic_mirror_filter_rul_source_cidr_block...

### 40. DescribeServiceLinkVirtualInterfaces

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.service_link_virtual_interfac_configuration_state, ec2.service_link_virtual_interfac_outpost_id, ec2.service_link_virtual_interfac_service_link_virtual_interface_arn, ec2.service_link_virtual_interfac_service_link_virtual_interface_id

### 41. DescribeVpcs

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.dhcp_option_dhcp_options_id, ec2.ipam_resource_discovery_is_default, ec2.vpc_cidr_block_association_set, ec2.vpc_encryption_control, ec2.vpcs

### 42. DescribeCapacityReservationFleets

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.capacity_reservation_fleet_allocation_strategy, ec2.capacity_reservation_fleet_capacity_reservation_fleet_arn, ec2.capacity_reservation_fleet_instance_type_specifications, ec2.capacity_reservation_fleet_total_fulfilled_capacity, ec2.capacity_reservation_fleet_total_target_capacity

### 43. DescribeCapacityManagerDataExports

- **Type:** Independent (Root)
- **Entities Covered:** 9
- **Covers:** ec2.capacity_manager_data_export_capacity_manager_data_export_id, ec2.capacity_manager_data_export_latest_delivery_s3_location_uri, ec2.capacity_manager_data_export_latest_delivery_status, ec2.capacity_manager_data_export_latest_delivery_status_message, ec2.capacity_manager_data_export_latest_delivery_time...

### 44. DescribeFastSnapshotRestores

- **Type:** Independent (Root)
- **Entities Covered:** 7
- **Covers:** ec2.fast_launch_imag_state_transition_reason, ec2.fast_snapshot_restor_availability_zone, ec2.fast_snapshot_restor_disabled_time, ec2.fast_snapshot_restor_disabling_time, ec2.fast_snapshot_restor_enabled_time...

### 45. DescribeSnapshotTierStatus

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.snapshot_tier_status_archival_complete_time, ec2.snapshot_tier_status_last_tiering_operation_status, ec2.snapshot_tier_status_last_tiering_operation_status_detail, ec2.snapshot_tier_status_last_tiering_progress, ec2.snapshot_tier_status_last_tiering_start_time

### 46. DescribeIpamExternalResourceVerificationTokens

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.ipam_arn, ec2.ipam_external_resource_verification_token_ipam_external_resource_verification_token_arn, ec2.ipam_external_resource_verification_token_ipam_external_resource_verification_token_id, ec2.ipam_external_resource_verification_token_not_after, ec2.ipam_external_resource_verification_token_token_name...

### 47. DescribeNetworkInsightsAccessScopeAnalyses

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.network_insights_access_scope_analys_analyzed_eni_count, ec2.network_insights_access_scope_analys_findings_found, ec2.network_insights_access_scope_analys_network_insights_access_scope_analysis_arn, ec2.network_insights_access_scope_analys_network_insights_access_scope_analysis_id, ec2.network_insights_access_scope_analys_network_insights_access_scope_id

### 48. DescribeIpamScopes

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.ipam_scop_description, ec2.ipam_scop_external_authority_configuration, ec2.ipam_scop_ipam_scope_id, ec2.ipam_scop_pool_count

### 49. DescribeAvailabilityZones

- **Type:** Independent (Root)
- **Entities Covered:** 10
- **Covers:** ec2.availability_zon_group_long_name, ec2.availability_zon_group_name, ec2.availability_zon_messages, ec2.availability_zon_opt_in_status, ec2.availability_zon_parent_zone_id...

### 50. DescribeVerifiedAccessGroups

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.verified_access_group_arn, ec2.verified_access_group_owner, ec2.verified_access_group_verified_access_group_arn

### 51. DescribeCapacityBlocks

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.capacity_block_availability_zone, ec2.capacity_block_capacity_reservation_ids, ec2.capacity_block_ultraserver_type

### 52. DescribeLaunchTemplateVersions

- **Type:** Independent (Root)
- **Entities Covered:** 8
- **Covers:** ec2.launch_template_id, ec2.launch_template_version_created_by, ec2.launch_template_version_default_version, ec2.launch_template_version_launch_template_data, ec2.launch_template_version_launch_template_id...

### 53. DescribeReservedInstancesModifications

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.reserved_instances_listing_update_date, ec2.reserved_instances_modification_client_token, ec2.reserved_instances_modification_effective_date, ec2.reserved_instances_modification_modification_results, ec2.reserved_instances_modification_reserved_instances_ids...

### 54. DescribeIpamPrefixListResolvers

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.ipam_prefix_list_resolver_address_family, ec2.ipam_prefix_list_resolver_ipam_prefix_list_resolver_arn, ec2.ipam_prefix_list_resolver_last_version_creation_status, ec2.ipam_prefix_list_resolver_last_version_creation_status_message, ec2.ipam_prefix_list_resolver_target_ipam_prefix_list_resolver_id

### 55. DescribeReservedInstancesListings

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.reserved_instances_listing_client_token, ec2.reserved_instances_listing_instance_counts, ec2.reserved_instances_listing_price_schedules, ec2.reserved_instances_listing_reserved_instances_listing_id

### 56. DescribeIpamResourceDiscoveryAssociations

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.ipam_resource_discovery_association_arn, ec2.ipam_resource_discovery_association_ipam_resource_discovery_association_arn, ec2.ipam_resource_discovery_association_ipam_resource_discovery_association_id, ec2.ipam_resource_discovery_association_resource_discovery_status, ec2.ipam_resource_discovery_ipam_resource_discovery_id

### 57. DescribeIpamPrefixListResolverTargets

- **Type:** Independent (Root)
- **Entities Covered:** 7
- **Covers:** ec2.ipam_prefix_list_resolver_target_arn, ec2.ipam_prefix_list_resolver_target_desired_version, ec2.ipam_prefix_list_resolver_target_ipam_prefix_list_resolver_target_arn, ec2.ipam_prefix_list_resolver_target_ipam_prefix_list_resolver_target_id, ec2.ipam_prefix_list_resolver_target_last_synced_version...

### 58. DescribeInstanceStatus

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.instance_status_attached_ebs_status, ec2.instance_status_events, ec2.instance_status_instance_state, ec2.instance_status_instance_status, ec2.instance_status_system_status

### 59. DescribeManagedPrefixLists

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.prefix_address_family, ec2.prefix_list_ipam_prefix_list_resolver_sync_enabled, ec2.prefix_list_max_entries, ec2.prefix_list_prefix_list_arn, ec2.prefix_list_prefix_list_name...

### 60. DescribeInstanceImageMetadata

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.instance_image_metadata, ec2.instance_image_metadata_image_metadata, ec2.instance_image_metadata_launch_time

### 61. DescribeReplaceRootVolumeTasks

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.mac_modification_task_task_state, ec2.replace_root_volume_task_complete_time, ec2.replace_root_volume_task_delete_replaced_root_volume, ec2.replace_root_volume_task_replace_root_volume_task_id

### 62. DescribeVolumeStatus

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.volume_status_actions, ec2.volume_status_attachment_statuses, ec2.volume_status_initialization_status_details, ec2.volume_status_volume_status

### 63. DescribeExportImageTasks

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.export_image_task_description, ec2.export_image_task_export_image_task_id, ec2.export_image_task_s3_export_location

### 64. DescribeSecurityGroups

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.client_vpn_target_network_security_groups, ec2.security_group_ip_permissions, ec2.security_group_ip_permissions_egress, ec2.security_group_security_group_arn

### 65. DescribeLockedSnapshots

- **Type:** Independent (Root)
- **Entities Covered:** 7
- **Covers:** ec2.snapshot_cool_off_period, ec2.snapshot_cool_off_period_expires_on, ec2.snapshot_lock_created_on, ec2.snapshot_lock_duration, ec2.snapshot_lock_duration_start_time...

### 66. DescribeTrafficMirrorSessions

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.traffic_mirror_session_description, ec2.traffic_mirror_session_packet_length, ec2.traffic_mirror_session_session_number, ec2.traffic_mirror_session_traffic_mirror_session_id, ec2.traffic_mirror_session_traffic_mirror_target_id...

### 67. DescribeTransitGatewayRouteTableAnnouncements

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.transit_gateway_route_table_announcement_announcement_direction, ec2.transit_gateway_route_table_announcement_core_network_id, ec2.transit_gateway_route_table_announcement_peer_core_network_id, ec2.transit_gateway_route_table_announcement_peer_transit_gateway_id, ec2.transit_gateway_route_table_announcement_peering_attachment_id...

### 68. DescribeIpamResourceDiscoveries

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.ipam_resource_discoveries, ec2.ipam_resource_discovery_ipam_resource_discovery_arn, ec2.ipam_resource_discovery_ipam_resource_discovery_region, ec2.ipam_resource_discovery_organizational_unit_exclusions

### 69. DescribeVpcBlockPublicAccessExclusions

- **Type:** Independent (Root)
- **Entities Covered:** 7
- **Covers:** ec2.exclusion_id, ec2.vpc_block_public_access_exclusion_deletion_timestamp, ec2.vpc_block_public_access_exclusion_exclusion_id, ec2.vpc_block_public_access_exclusion_internet_gateway_exclusion_mode, ec2.vpc_block_public_access_exclusion_last_update_timestamp...

### 70. DescribeVpcEndpointConnectionNotifications

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.connection_notification_set, ec2.connection_notification_set_connection_events, ec2.connection_notification_set_connection_notification_arn, ec2.connection_notification_set_connection_notification_id, ec2.connection_notification_set_connection_notification_state...

### 71. DescribeLaunchTemplates

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.launch_templat_create_time, ec2.launch_templat_default_version_number, ec2.launch_templat_latest_version_number

### 72. DescribeDeclarativePoliciesReports

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.report_report_id, ec2.report_s3_bucket, ec2.report_s3_prefix, ec2.report_target_id, ec2.reports

### 73. DescribeHostReservationOfferings

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.offering_set

### 74. DescribeImageUsageReports

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.conversion_task_expiration_time, ec2.image_usage_report_account_ids, ec2.image_usage_report_resource_types

### 75. DescribeInstanceTopology

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.capacity_reservation_network_nodes

### 76. DescribeInstanceSqlHaHistoryStates

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.instanc_ha_status, ec2.instanc_processing_status, ec2.instanc_sql_server_credentials, ec2.instanc_sql_server_license_usage

### 77. DescribeMacModificationTasks

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.mac_modification_task_id, ec2.mac_modification_task_mac_modification_task_id, ec2.mac_modification_task_mac_system_integrity_protection_config, ec2.mac_modification_task_task_type

### 78. GetAwsNetworkPerformanceData

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.data_respons_destination, ec2.data_respons_metric_points, ec2.subscription_metric, ec2.subscription_period, ec2.subscription_statistic

### 79. DescribeTransitGatewayVpcAttachments

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.security_group_vpc_association_vpc_owner_id, ec2.transit_gateway_vpc_attachment_creation_time

### 80. DescribePublicIpv4Pools

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.coip_pool_pool_id, ec2.public_ipv4_pool_description, ec2.public_ipv4_pool_pool_address_ranges, ec2.public_ipv4_pool_total_address_count, ec2.public_ipv4_pool_total_available_address_count

### 81. DescribeLocalGatewayVirtualInterfaceGroups

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.local_gateway_virtual_interface_group_arn, ec2.local_gateway_virtual_interface_group_local_bgp_asn_extended, ec2.local_gateway_virtual_interface_group_local_gateway_virtual_interface_group_arn, ec2.local_gateway_virtual_interface_group_local_gateway_virtual_interface_ids

### 82. DescribeElasticGpus

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.elastic_gpu_set, ec2.elastic_gpu_set_elastic_gpu_health, ec2.elastic_gpu_set_elastic_gpu_id, ec2.elastic_gpu_set_elastic_gpu_state, ec2.elastic_gpu_set_elastic_gpu_type

### 83. DescribeVerifiedAccessInstances

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.verified_access_instanc_cidr_endpoints_custom_sub_domain, ec2.verified_access_instanc_fips_enabled

### 84. DescribeIpamPolicies

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.ipam_policies, ec2.ipam_policy_ipam_policy_arn, ec2.ipam_policy_ipam_policy_id, ec2.ipam_policy_ipam_policy_region

### 85. DescribeTransitGatewayRouteTables

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.transit_gateway_route_tabl_creation_time, ec2.transit_gateway_route_tabl_default_association_route_table, ec2.transit_gateway_route_tabl_default_propagation_route_table

### 86. DescribeTransitGatewayMulticastDomains

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.transit_gateway_multicast_domain_arn, ec2.transit_gateway_multicast_domain_transit_gateway_multicast_domain_arn, ec2.transit_gateway_multicast_domain_transit_gateway_multicast_domain_id

### 87. DescribeTrunkInterfaceAssociations

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.interface_association_branch_interface_id, ec2.interface_association_gre_key, ec2.interface_association_interface_protocol, ec2.interface_association_trunk_interface_id, ec2.interface_association_vlan_id

### 88. DescribeTransitGateways

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.transit_gateway_arn, ec2.transit_gateway_transit_gateway_arn

### 89. DescribeBundleTasks

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.bundle_id, ec2.bundle_task_bundle_id, ec2.bundle_task_bundle_task_error, ec2.bundle_task_storage

### 90. DescribeStoreImageTasks

- **Type:** Independent (Root)
- **Entities Covered:** 7
- **Covers:** ec2.spot_datafeed_subscription_bucket, ec2.store_image_task_result_ami_id, ec2.store_image_task_result_progress_percentage, ec2.store_image_task_result_s3object_key, ec2.store_image_task_result_store_task_failure_reason...

### 91. DescribeRouteTables

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.network_acl_associations, ec2.route_tabl_associations, ec2.route_tabl_propagating_vgws

### 92. DescribeVpcEncryptionControls

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.local_gateway_route_tabl_mode, ec2.vpc_encryption_control_id, ec2.vpc_encryption_control_resource_exclusions, ec2.vpc_encryption_control_vpc_encryption_control_id

### 93. DescribeTrafficMirrorFilters

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.traffic_mirror_filter_description, ec2.traffic_mirror_filter_egress_filter_rules, ec2.traffic_mirror_filter_ingress_filter_rules, ec2.traffic_mirror_filter_network_services

### 94. DescribeTransitGatewayPeeringAttachments

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.transit_gateway_peering_attachment_accepter_tgw_info, ec2.transit_gateway_peering_attachment_accepter_transit_gateway_attachment_id, ec2.transit_gateway_peering_attachment_requester_tgw_info

### 95. DescribeRouteServerEndpoints

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.route_server_endpoint_eni_address, ec2.route_server_endpoint_eni_id

### 96. DescribeSpotFleetRequests

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.spot_fleet_request_config_activity_status, ec2.spot_fleet_request_config_spot_fleet_request_config, ec2.spot_fleet_request_config_spot_fleet_request_id, ec2.spot_fleet_request_config_spot_fleet_request_state

### 97. DescribeCapacityBlockStatus

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.capacity_block_id, ec2.capacity_block_status_capacity_reservation_statuses, ec2.capacity_block_status_interconnect_status, ec2.capacity_block_status_total_available_capacity, ec2.capacity_block_status_total_capacity...

### 98. DescribeVpcBlockPublicAccessOptions

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.network_interface_permission_aws_account_id, ec2.vpc_block_public_access_option_aws_account_id, ec2.vpc_block_public_access_option_aws_region, ec2.vpc_block_public_access_option_exclusions_allowed, ec2.vpc_block_public_access_option_internet_gateway_block_mode...

### 99. DescribeRouteServers

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.route_server_amazon_side_asn, ec2.route_server_persist_routes_duration, ec2.route_server_persist_routes_state, ec2.route_server_sns_notifications_enabled, ec2.route_server_sns_topic_arn

### 100. DescribeKeyPairs

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.key_name, ec2.key_pair_key_fingerprint, ec2.key_pair_key_name, ec2.key_pair_key_pair_id, ec2.key_pair_key_type...

### 101. DescribeSpotPriceHistory

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.iam_instance_profile_association_timestamp, ec2.spot_price_history

### 102. DescribeAwsNetworkPerformanceMetricSubscriptions

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.subscriptions

### 103. DescribeExportTasks

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.export_task_description, ec2.export_task_export_task_id, ec2.export_task_export_to_s3_task, ec2.export_task_instance_export_details

### 104. DescribeTransitGatewayMeteringPolicies

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.transit_gateway_metering_policies, ec2.transit_gateway_metering_policy_middlebox_attachment_ids, ec2.transit_gateway_metering_policy_transit_gateway_metering_policy_id, ec2.transit_gateway_metering_policy_update_effective_at

### 105. DescribeOutpostLags

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.outpost_lag_id, ec2.outpost_lag_service_link_virtual_interface_ids

### 106. DescribePlacementGroups

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.placement_group_group_arn, ec2.placement_group_partition_count, ec2.placement_group_spread_level, ec2.placement_group_strategy

### 107. DescribeFastLaunchImages

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.fast_launch_imag_launch_template, ec2.fast_launch_imag_max_parallel_launches, ec2.fast_launch_imag_snapshot_configuration, ec2.fast_launch_imag_state_transition_time

### 108. DescribeTrafficMirrorTargets

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.traffic_mirror_target_description, ec2.traffic_mirror_target_gateway_load_balancer_endpoint_id, ec2.traffic_mirror_target_network_load_balancer_arn

### 109. DescribeNetworkAcls

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.network_acl_entries, ec2.network_acl_network_acl_id

### 110. DescribeTransitGatewayConnects

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.transit_gateway_connect_creation_time, ec2.transit_gateway_connect_transport_transit_gateway_attachment_id

### 111. GetAllowedImagesSettings

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.image_criteria, ec2.image_criteria_creation_date_condition, ec2.image_criteria_deprecation_time_condition, ec2.image_criteria_image_names, ec2.image_criteria_image_providers...

### 112. DescribeCustomerGateways

- **Type:** Independent (Root)
- **Entities Covered:** 5
- **Covers:** ec2.customer_gateway_bgp_asn, ec2.customer_gateway_bgp_asn_extended, ec2.customer_gateway_certificate_arn, ec2.customer_gateway_device_name, ec2.customer_gateway_ip_address

### 113. DescribeImageUsageReportEntries

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.image_usage_report_entries, ec2.image_usage_report_entry_account_id, ec2.image_usage_report_entry_report_creation_time, ec2.image_usage_report_entry_usage_count

### 114. DescribeVpcPeeringConnections

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.vpc_peering_connection_accepter_vpc_info, ec2.vpc_peering_connection_requester_vpc_info, ec2.vpc_peering_connection_vpc_peering_connection_id

### 115. GetInstanceMetadataDefaults

- **Type:** Independent (Root)
- **Entities Covered:** 6
- **Covers:** ec2.account_level, ec2.account_level_http_endpoint, ec2.account_level_http_put_response_hop_limit, ec2.account_level_http_tokens, ec2.account_level_instance_metadata_tags...

### 116. DescribeSecurityGroupVpcAssociations

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.security_group_vpc_association_state

### 117. DescribeInstanceEventWindows

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.instance_event_window_association_target, ec2.instance_event_window_cron_expression, ec2.instance_event_window_instance_event_window_id, ec2.instance_event_window_time_ranges

### 118. DescribeAddressTransfers

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.address_transfer_address_transfer_status, ec2.address_transfer_transfer_account_id, ec2.address_transfer_transfer_offer_accepted_timestamp, ec2.address_transfer_transfer_offer_expiration_timestamp

### 119. DescribeVpnGateways

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.vpn_gateway_amazon_side_asn, ec2.vpn_gateway_vpc_attachments

### 120. DescribeCoipPools

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.coip_pool_local_gateway_route_table_id, ec2.coip_pool_pool_arn, ec2.coip_pool_pool_cidrs

### 121. DescribeNetworkInterfacePermissions

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.network_interface_permission_network_interface_permission_id, ec2.network_interface_permission_permission, ec2.network_interface_permission_permission_state

### 122. DescribeLocalGatewayRouteTableVpcAssociations

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.local_gateway_route_table_vpc_association_local_gateway_route_table_arn, ec2.local_gateway_route_table_vpc_association_local_gateway_route_table_vpc_association_id

### 123. DescribeConversionTasks

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.conversion_task_conversion_task_id, ec2.conversion_task_import_instance, ec2.conversion_task_import_volume

### 124. DescribeNetworkInsightsAccessScopes

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.network_insights_access_scop_network_insights_access_scope_arn, ec2.network_insights_access_scop_updated_date

### 125. DescribeIpv6Pools

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.ipv6_pool_description, ec2.ipv6_pool_pool_cidr_blocks

### 126. DescribeTransitGatewayAttachments

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.transit_gateway_attachment_transit_gateway_owner_id

### 127. DescribeImportSnapshotTasks

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.import_snapshot_task_description, ec2.import_snapshot_task_snapshot_task_detail

### 128. DescribeTransitGatewayPolicyTables

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.transit_gateway_policy_tabl_creation_time, ec2.transit_gateway_policy_tabl_transit_gateway_policy_table_id

### 129. GetVpnConnectionDeviceTypes

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.vpn_connection_device_typ_platform, ec2.vpn_connection_device_typ_software, ec2.vpn_connection_device_typ_vendor, ec2.vpn_connection_device_typ_vpn_connection_device_type_id

### 130. DescribeInstances

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.reservation_reservation_id, ec2.reservations

### 131. DescribeInternetGateways

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.internet_gateway_attachments, ec2.internet_gateway_internet_gateway_id

### 132. DescribeCarrierGateways

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.carrier_gateway_carrier_gateway_id, ec2.carrier_gateway_state

### 133. DescribeAddressesAttribute

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.address_ptr_record, ec2.address_ptr_record_update

### 134. DescribeLocalGateways

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.local_gateway_state

### 135. DescribeIpamByoasn

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.byoasn_asn, ec2.byoasns

### 136. DescribeInstanceTypeOfferings

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.instance_type_offering_instance_type, ec2.instance_type_offering_location, ec2.instance_type_offering_location_type

### 137. DescribeTransitGatewayConnectPeers

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.transit_gateway_connect_peer_connect_peer_configuration, ec2.transit_gateway_connect_peer_transit_gateway_connect_peer_id

### 138. DescribeIamInstanceProfileAssociations

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.iam_instance_profile_association_iam_instance_profile

### 139. DescribeVpnConcentrators

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.vpn_concentrator_id

### 140. DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.group_id, ec2.local_gateway_route_table_virtual_interface_group_association_local_gateway_route_table_virtual_interface_group_association_id

### 141. DescribeDhcpOptions

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.dhcp_option_dhcp_configurations

### 142. DescribeTags

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.tag_key, ec2.tag_value

### 143. DescribeAggregateIdFormat

- **Type:** Independent (Root)
- **Entities Covered:** 4
- **Covers:** ec2.principal_statuses, ec2.status_deadline, ec2.status_resource, ec2.status_use_long_ids

### 144. DescribeSpotDatafeedSubscription

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.spot_datafeed_subscription, ec2.spot_datafeed_subscription_prefix

### 145. DescribePrincipalIdFormat

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.principal_arn, ec2.principals

### 146. DescribePrefixLists

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.prefix_list_cidrs

### 147. DescribeVpcClassicLink

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.vpc_classic_link_enabled

### 148. DescribeMacHosts

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.mac_host_host_id, ec2.mac_host_mac_os_latest_supported_versions

### 149. DescribeEgressOnlyInternetGateways

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.egress_only_internet_gateway_egress_only_internet_gateway_id

### 150. DescribeRegions

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.region_endpoint, ec2.regions

### 151. DescribeVpcClassicLinkDnsSupport

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.vpc_classic_link_dns_supported

### 152. GetEnabledIpamPolicy

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.ipam_policy_enabled

### 153. DescribeVerifiedAccessInstanceLoggingConfigurations

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.logging_configuration_access_logs

### 154. DescribeInstanceCreditSpecifications

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.instance_credit_specification_cpu_credits

### 155. DescribeInstanceEventNotificationAttributes

- **Type:** Independent (Root)
- **Entities Covered:** 3
- **Covers:** ec2.instance_tag_attribute, ec2.instance_tag_attribute_include_all_tags_of_instance, ec2.instance_tag_attribute_instance_tag_keys

### 156. GetImageBlockPublicAccessState

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.image_block_public_access_state

### 157. GetEbsEncryptionByDefault

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.ebs_encryption_by_default

### 158. DescribeMovingAddresses

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.moving_address_status_move_status

### 159. GetSerialConsoleAccessStatus

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.serial_console_access_enabled

### 160. DescribeVpcEndpointServices

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.service_details

### 161. DescribeAccountAttributes

- **Type:** Independent (Root)
- **Entities Covered:** 2
- **Covers:** ec2.account_attribut_attribute_name, ec2.account_attribut_attribute_values

### 162. GetCapacityManagerAttributes

- **Type:** Independent (Root)
- **Entities Covered:** 1
- **Covers:** ec2.capacity_manager_status

## ⚠️  Dependent Operations

These operations require inputs from other operations:

### 1. GetLaunchTemplateData

- **Type:** Dependent
- **Entities Covered:** 21
- **Covers:** ec2.launch_template_data_capacity_reservation_specification, ec2.launch_template_data_cpu_options, ec2.launch_template_data_credit_specification, ec2.launch_template_data_disable_api_stop, ec2.launch_template_data_disable_api_termination...
- **Requires:** ec2.address_instance_id
- **Dependencies:** ec2.address_instance_id

### 2. DescribeClientVpnConnections

- **Type:** Dependent
- **Entities Covered:** 12
- **Covers:** ec2.connection_client_ip, ec2.connection_client_ipv6_address, ec2.connection_common_name, ec2.connection_connection_end_time, ec2.connection_connection_established_time...
- **Requires:** ec2.client_vpn_endpoint_client_vpn_endpoint_id
- **Dependencies:** ec2.client_vpn_endpoint_client_vpn_endpoint_id

### 3. GetCapacityManagerMetricDimensions

- **Type:** Dependent
- **Entities Covered:** 9
- **Covers:** ec2.metric_dimension_result_reservation_arn, ec2.metric_dimension_result_reservation_create_timestamp, ec2.metric_dimension_result_reservation_end_date_type, ec2.metric_dimension_result_reservation_end_timestamp, ec2.metric_dimension_result_reservation_instance_match_criteria...
- **Requires:** ec2.bundle_task_start_time, ec2.report_end_time
- **Dependencies:** ec2.bundle_task_start_time, ec2.report_end_time

### 4. GetActiveVpnTunnelStatus

- **Type:** Dependent
- **Entities Covered:** 9
- **Covers:** ec2.active_vpn_tunnel_statu_ike_version, ec2.active_vpn_tunnel_statu_phase1_dh_group, ec2.active_vpn_tunnel_statu_phase1_encryption_algorithm, ec2.active_vpn_tunnel_statu_phase1_integrity_algorithm, ec2.active_vpn_tunnel_statu_phase2_dh_group...
- **Requires:** ec2.vpn_connection_vpn_connection_id
- **Dependencies:** ec2.vpn_connection_vpn_connection_id

### 5. GetIpamResourceCidrs

- **Type:** Dependent
- **Entities Covered:** 7
- **Covers:** ec2.history_record_resource_cidr, ec2.history_record_resource_name, ec2.ipam_discovered_resource_cidr_ip_usage, ec2.ipam_discovered_resource_cidr_resource_tags, ec2.ipam_resource_cidr_compliance_status...
- **Requires:** ec2.ipam_scop_ipam_scope_id
- **Dependencies:** ec2.ipam_scop_ipam_scope_id

### 6. DescribeImageAttribute

- **Type:** Dependent
- **Entities Covered:** 5
- **Covers:** ec2.boot_mode, ec2.launch_permission_group, ec2.launch_permission_organization_arn, ec2.launch_permission_organizational_unit_arn, ec2.launch_permission_user_id
- **Requires:** ec2.export_image_task_image_id
- **Dependencies:** ec2.export_image_task_image_id

### 7. GetDeclarativePoliciesReportSummary

- **Type:** Dependent
- **Entities Covered:** 5
- **Covers:** ec2.attribute_most_frequent_value, ec2.attribute_summary_most_frequent_value, ec2.attribute_summary_number_of_matched_accounts, ec2.attribute_summary_number_of_unmatched_accounts, ec2.attribute_summary_regional_summaries
- **Requires:** ec2.report_report_id
- **Dependencies:** ec2.report_report_id

### 8. GetRouteServerRoutingDatabase

- **Type:** Dependent
- **Entities Covered:** 5
- **Covers:** ec2.rout_as_paths, ec2.rout_med, ec2.rout_next_hop_ip, ec2.rout_route_installation_details, ec2.rout_route_status
- **Requires:** ec2.route_server_endpoint_route_server_id
- **Dependencies:** ec2.route_server_endpoint_route_server_id

### 9. DescribeCapacityBlockOfferings

- **Type:** Dependent
- **Entities Covered:** 4
- **Covers:** ec2.capacity_block_offering_capacity_block_duration_hours, ec2.capacity_block_offering_capacity_block_duration_minutes, ec2.capacity_block_offering_capacity_block_offering_id, ec2.capacity_block_offering_ultraserver_count

### 10. DescribeScheduledInstanceAvailability

- **Type:** Dependent
- **Entities Covered:** 4
- **Covers:** ec2.scheduled_instance_availability_set_first_slot_start_time, ec2.scheduled_instance_availability_set_max_term_duration_in_days, ec2.scheduled_instance_availability_set_min_term_duration_in_days, ec2.scheduled_instance_availability_set_purchase_token
- **Requires:** ec2.scheduled_instance_set_recurrence
- **Dependencies:** ec2.scheduled_instance_set_recurrence

### 11. GetIpamPrefixListResolverRules

- **Type:** Dependent
- **Entities Covered:** 4
- **Covers:** ec2.rul_conditions, ec2.rul_rule_type, ec2.rul_rules, ec2.rul_static_cidr
- **Requires:** ec2.ipam_prefix_list_resolver_target_ipam_prefix_list_resolver_id
- **Dependencies:** ec2.ipam_prefix_list_resolver_target_ipam_prefix_list_resolver_id

### 12. GetIpamPoolCidrs

- **Type:** Dependent
- **Entities Covered:** 4
- **Covers:** ec2.byoip_cidr_cidr, ec2.ipam_pool_cidr_ipam_pool_cidr_id, ec2.ipam_pool_cidr_ipam_pool_cidrs, ec2.ipam_pool_cidr_netmask_length
- **Requires:** ec2.ipam_pool_ipam_pool_id
- **Dependencies:** ec2.ipam_pool_ipam_pool_id

### 13. GetIpamAddressHistory

- **Type:** Dependent
- **Entities Covered:** 4
- **Covers:** ec2.history_record_resource_compliance_status, ec2.history_record_resource_overlap_status, ec2.history_record_sampled_end_time, ec2.history_record_sampled_start_time
- **Requires:** ec2.byoip_cidr_cidr, ec2.ipam_scop_ipam_scope_id
- **Dependencies:** ec2.byoip_cidr_cidr, ec2.ipam_scop_ipam_scope_id

### 14. GetAssociatedEnclaveCertificateIamRoles

- **Type:** Dependent
- **Entities Covered:** 4
- **Covers:** ec2.associated_rol_associated_role_arn, ec2.associated_rol_certificate_s3_bucket_name, ec2.associated_rol_certificate_s3_object_key, ec2.associated_rol_encryption_kms_key_id
- **Requires:** ec2.certificate_arn
- **Dependencies:** ec2.certificate_arn

### 15. GetIpamDiscoveredResourceCidrs

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** ec2.ipam_discovered_public_address_sample_time, ec2.ipam_discovered_resource_cidr_ip_source, ec2.ipam_discovered_resource_cidr_network_interface_attachment_status
- **Requires:** ec2.ipam_resource_discovery_ipam_resource_discovery_id, ec2.metric_dimension_result_resource_region
- **Dependencies:** ec2.ipam_resource_discovery_ipam_resource_discovery_id, ec2.metric_dimension_result_resource_region

### 16. DescribeClientVpnRoutes

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** ec2.authorization_rul_destination_cidr, ec2.rout_origin, ec2.rout_target_subnet
- **Requires:** ec2.client_vpn_endpoint_client_vpn_endpoint_id
- **Dependencies:** ec2.client_vpn_endpoint_client_vpn_endpoint_id

### 17. DescribeCapacityReservationBillingRequests

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** ec2.capacity_reservation_billing_request_capacity_reservation_info, ec2.capacity_reservation_billing_request_last_update_time, ec2.capacity_reservation_billing_request_requested_by

### 18. DescribeStaleSecurityGroups

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** ec2.stale_security_group_set, ec2.stale_security_group_set_stale_ip_permissions, ec2.stale_security_group_set_stale_ip_permissions_egress
- **Requires:** ec2.carrier_gateway_vpc_id
- **Dependencies:** ec2.carrier_gateway_vpc_id

### 19. GetVpnTunnelReplacementStatus

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** ec2.maintenance_detail_last_maintenance_applied, ec2.maintenance_detail_maintenance_auto_applied_after, ec2.maintenance_detail_pending_maintenance
- **Requires:** ec2.vpn_connection_vpn_connection_id
- **Dependencies:** ec2.vpn_connection_vpn_connection_id

### 20. DescribeVpcEndpointServicePermissions

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** ec2.allowed_principal_principal, ec2.allowed_principal_principal_type, ec2.allowed_principal_service_permission_id
- **Requires:** ec2.connection_notification_set_service_id
- **Dependencies:** ec2.connection_notification_set_service_id

### 21. GetTransitGatewayMeteringPolicyEntries

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** ec2.transit_gateway_metering_policy_entry_metering_policy_rule, ec2.transit_gateway_metering_policy_entry_policy_rule_number, ec2.transit_gateway_metering_policy_entry_updated_at
- **Requires:** ec2.transit_gateway_metering_policy_transit_gateway_metering_policy_id
- **Dependencies:** ec2.transit_gateway_metering_policy_transit_gateway_metering_policy_id

### 22. DescribeSnapshotAttribute

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** ec2.create_volume_permissions, ec2.product_cod_product_code_id, ec2.product_cod_product_code_type
- **Requires:** ec2.fast_snapshot_restor_snapshot_id
- **Dependencies:** ec2.fast_snapshot_restor_snapshot_id

### 23. GetTransitGatewayPrefixListReferences

- **Type:** Dependent
- **Entities Covered:** 3
- **Covers:** ec2.transit_gateway_prefix_list_referenc_blackhole, ec2.transit_gateway_prefix_list_referenc_prefix_list_owner_id, ec2.transit_gateway_prefix_list_referenc_transit_gateway_attachment
- **Requires:** ec2.transit_gateway_route_table_announcement_transit_gateway_route_table_id
- **Dependencies:** ec2.transit_gateway_route_table_announcement_transit_gateway_route_table_id

### 24. GetHostReservationPurchasePreview

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.purchase_purchase, ec2.purchase_total_hourly_price
- **Requires:** ec2.host_reservation_set_host_id_set, ec2.offering_set_offering_id
- **Dependencies:** ec2.host_reservation_set_host_id_set, ec2.offering_set_offering_id

### 25. DescribeClientVpnTargetNetworks

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.client_vpn_target_network_client_vpn_target_networks, ec2.client_vpn_target_network_target_network_id
- **Requires:** ec2.client_vpn_endpoint_client_vpn_endpoint_id
- **Dependencies:** ec2.client_vpn_endpoint_client_vpn_endpoint_id

### 26. DescribeByoipCidrs

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.byoip_cidr_advertisement_type, ec2.byoip_cidr_asn_associations
- **Requires:** ec2.elastic_gpu_set
- **Dependencies:** ec2.elastic_gpu_set

### 27. GetSecurityGroupsForVpc

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.security_group_for_vpc_description, ec2.security_group_for_vpc_primary_vpc_id
- **Requires:** ec2.carrier_gateway_vpc_id
- **Dependencies:** ec2.carrier_gateway_vpc_id

### 28. DescribeFleetHistory

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.history_record_event_information, ec2.history_record_event_type
- **Requires:** ec2.bundle_task_start_time, ec2.fleet_fleet_id
- **Dependencies:** ec2.bundle_task_start_time, ec2.fleet_fleet_id

### 29. GetIpamPoolAllocations

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.ipam_pool_allocation_ipam_pool_allocation_id, ec2.ipam_pool_allocation_resource_owner
- **Requires:** ec2.ipam_pool_ipam_pool_id
- **Dependencies:** ec2.ipam_pool_ipam_pool_id

### 30. GetCoipPoolUsage

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.coip_address_usag_aws_account_id, ec2.coip_address_usag_co_ip
- **Requires:** ec2.coip_pool_pool_id
- **Dependencies:** ec2.coip_pool_pool_id

### 31. DescribeSecurityGroupReferences

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.security_group_reference_set, ec2.security_group_reference_set_referencing_vpc_id
- **Requires:** ec2.group_id
- **Dependencies:** ec2.group_id

### 32. GetNetworkInsightsAccessScopeAnalysisFindings

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.analysis_finding_finding_components, ec2.analysis_finding_finding_id
- **Requires:** ec2.network_insights_access_scope_analys_network_insights_access_scope_analysis_id
- **Dependencies:** ec2.network_insights_access_scope_analys_network_insights_access_scope_analysis_id

### 33. GetVpcResourcesBlockingEncryptionEnforcement

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.non_compliant_resourc_description, ec2.non_compliant_resourc_is_excludable
- **Requires:** ec2.carrier_gateway_vpc_id
- **Dependencies:** ec2.carrier_gateway_vpc_id

### 34. GetSpotPlacementScores

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.spot_placement_scor_region, ec2.spot_placement_scor_score

### 35. GetCapacityManagerMetricData

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.metric_data_result_dimension, ec2.metric_data_result_metric_values
- **Requires:** ec2.bundle_task_start_time, ec2.report_end_time, ec2.subscription_period
- **Dependencies:** ec2.bundle_task_start_time, ec2.report_end_time, ec2.subscription_period

### 36. GetVerifiedAccessEndpointTargets

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.verified_access_endpoint_target_verified_access_endpoint_target_dns, ec2.verified_access_endpoint_target_verified_access_endpoint_target_ip_address
- **Requires:** ec2.verified_access_endpoint_verified_access_endpoint_id
- **Dependencies:** ec2.verified_access_endpoint_verified_access_endpoint_id

### 37. GetTransitGatewayPolicyTableEntries

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.transit_gateway_policy_table_entry_policy_rule, ec2.transit_gateway_policy_table_entry_target_route_table_id
- **Requires:** ec2.transit_gateway_policy_tabl_transit_gateway_policy_table_id
- **Dependencies:** ec2.transit_gateway_policy_tabl_transit_gateway_policy_table_id

### 38. GetNetworkInsightsAccessScopeContent

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.network_insights_access_scope_content_exclude_paths, ec2.network_insights_access_scope_content_match_paths
- **Requires:** ec2.network_insights_access_scope_analys_network_insights_access_scope_id
- **Dependencies:** ec2.network_insights_access_scope_analys_network_insights_access_scope_id

### 39. GetAssociatedIpv6PoolCidrs

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.ipv6_cidr_association_associated_resource, ec2.ipv6_cidr_association_ipv6_cidr
- **Requires:** ec2.coip_pool_pool_id
- **Dependencies:** ec2.coip_pool_pool_id

### 40. GetReservedInstancesExchangeQuote

- **Type:** Dependent
- **Entities Covered:** 2
- **Covers:** ec2.reserved_instance_value_set_reservation_value, ec2.reserved_instance_value_set_reserved_instance_id

### 41. GetCapacityReservationUsage

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.instance_usag_used_instance_count
- **Requires:** ec2.capacity_block_extension_capacity_reservation_id
- **Dependencies:** ec2.capacity_block_extension_capacity_reservation_id

### 42. DescribeNetworkInterfaceAttribute

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.associate_public_ip_address

### 43. DescribeClientVpnAuthorizationRules

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.authorization_rul_access_all
- **Requires:** ec2.client_vpn_endpoint_client_vpn_endpoint_id
- **Dependencies:** ec2.client_vpn_endpoint_client_vpn_endpoint_id

### 44. DescribeFleetInstances

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.active_instanc_instance_health
- **Requires:** ec2.fleet_fleet_id
- **Dependencies:** ec2.fleet_fleet_id

### 45. GetSubnetCidrReservations

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.subnet_ipv4_cidr_reservation_subnet_cidr_reservation_id

### 46. GetImageAncestry

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.image_ancestry_entries
- **Requires:** ec2.export_image_task_image_id
- **Dependencies:** ec2.export_image_task_image_id

### 47. DescribeFpgaImageAttribute

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.fpga_image_attribute_load_permissions
- **Requires:** ec2.fpga_imag_fpga_image_id
- **Dependencies:** ec2.fpga_imag_fpga_image_id

### 48. DescribeVolumeAttribute

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.auto_enable_io
- **Requires:** ec2.snapshot_tier_status_volume_id
- **Dependencies:** ec2.snapshot_tier_status_volume_id

### 49. GetIpamPolicyAllocationRules

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.ipam_policy_document_allocation_rules
- **Requires:** ec2.ipam_policy_ipam_policy_id
- **Dependencies:** ec2.ipam_policy_ipam_policy_id

### 50. GetGroupsForCapacityReservation

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.capacity_reservation_group_capacity_reservation_groups
- **Requires:** ec2.capacity_block_extension_capacity_reservation_id
- **Dependencies:** ec2.capacity_block_extension_capacity_reservation_id

### 51. DescribeVpcAttribute

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.enable_dns_hostnam_value
- **Requires:** ec2.carrier_gateway_vpc_id
- **Dependencies:** ec2.carrier_gateway_vpc_id

### 52. GetTransitGatewayMulticastDomainAssociations

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.multicast_domain_association_subnet
- **Requires:** ec2.transit_gateway_multicast_domain_transit_gateway_multicast_domain_id
- **Dependencies:** ec2.transit_gateway_multicast_domain_transit_gateway_multicast_domain_id

### 53. GetIpamPolicyOrganizationTargets

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.organization_target_organization_target_id
- **Requires:** ec2.ipam_policy_ipam_policy_id
- **Dependencies:** ec2.ipam_policy_ipam_policy_id

### 54. GetConsoleScreenshot

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.image_data_image_data
- **Requires:** ec2.address_instance_id
- **Dependencies:** ec2.address_instance_id

### 55. GetFlowLogsIntegrationTemplate

- **Type:** Dependent
- **Entities Covered:** 1
- **Covers:** ec2.result_result
- **Requires:** ec2.flow_log_flow_log_id
- **Dependencies:** ec2.flow_log_flow_log_id

---

## 📋 Complete Operations List (In Order)

### Independent Operations:
1. `DescribeImages`
1. `DescribeInstanceTypes`
1. `DescribeNetworkInterfaces`
1. `DescribeCapacityReservations`
1. `DescribeClientVpnEndpoints`
1. `DescribeVpcEndpoints`
1. `DescribeIpamPools`
1. `DescribeSnapshots`
1. `DescribeVolumes`
1. `DescribeFleets`
1. `DescribeVerifiedAccessEndpoints`
1. `DescribeSubnets`
1. `DescribeHosts`
1. `DescribeReservedInstances`
1. `DescribeVpcEndpointServiceConfigurations`
1. `DescribeImportImageTasks`
1. `DescribeSpotInstanceRequests`
1. `DescribeVolumesModifications`
1. `DescribeIpams`
1. `DescribeReservedInstancesOfferings`
1. `DescribeNetworkInsightsAnalyses`
1. `DescribeNatGateways`
1. `DescribeScheduledInstances`
1. `DescribeFlowLogs`
1. `DescribeInstanceConnectEndpoints`
1. `DescribeFpgaImages`
1. `ListVolumesInRecycleBin`
1. `DescribeNetworkInsightsPaths`
1. `DescribeVerifiedAccessTrustProviders`
1. `DescribeVpnConnections`
1. `DescribeAddresses`
1. `DescribeHostReservations`
1. `DescribeCapacityBlockExtensionHistory`
1. `DescribeLocalGatewayVirtualInterfaces`
1. `DescribeSecurityGroupRules`
1. `DescribeVpcEndpointConnections`
1. `DescribeRouteServerPeers`
1. `DescribeVpcEndpointAssociations`
1. `DescribeTrafficMirrorFilterRules`
1. `DescribeServiceLinkVirtualInterfaces`
1. `DescribeVpcs`
1. `DescribeCapacityReservationFleets`
1. `DescribeCapacityManagerDataExports`
1. `DescribeFastSnapshotRestores`
1. `DescribeSnapshotTierStatus`
1. `DescribeIpamExternalResourceVerificationTokens`
1. `DescribeNetworkInsightsAccessScopeAnalyses`
1. `DescribeIpamScopes`
1. `DescribeAvailabilityZones`
1. `DescribeVerifiedAccessGroups`
1. `DescribeCapacityBlocks`
1. `DescribeLaunchTemplateVersions`
1. `DescribeReservedInstancesModifications`
1. `DescribeIpamPrefixListResolvers`
1. `DescribeReservedInstancesListings`
1. `DescribeIpamResourceDiscoveryAssociations`
1. `DescribeIpamPrefixListResolverTargets`
1. `DescribeInstanceStatus`
1. `DescribeManagedPrefixLists`
1. `DescribeInstanceImageMetadata`
1. `DescribeReplaceRootVolumeTasks`
1. `DescribeVolumeStatus`
1. `DescribeExportImageTasks`
1. `DescribeSecurityGroups`
1. `DescribeLockedSnapshots`
1. `DescribeTrafficMirrorSessions`
1. `DescribeTransitGatewayRouteTableAnnouncements`
1. `DescribeIpamResourceDiscoveries`
1. `DescribeVpcBlockPublicAccessExclusions`
1. `DescribeVpcEndpointConnectionNotifications`
1. `DescribeLaunchTemplates`
1. `DescribeDeclarativePoliciesReports`
1. `DescribeHostReservationOfferings`
1. `DescribeImageUsageReports`
1. `DescribeInstanceTopology`
1. `DescribeInstanceSqlHaHistoryStates`
1. `DescribeMacModificationTasks`
1. `GetAwsNetworkPerformanceData`
1. `DescribeTransitGatewayVpcAttachments`
1. `DescribePublicIpv4Pools`
1. `DescribeLocalGatewayVirtualInterfaceGroups`
1. `DescribeElasticGpus`
1. `DescribeVerifiedAccessInstances`
1. `DescribeIpamPolicies`
1. `DescribeTransitGatewayRouteTables`
1. `DescribeTransitGatewayMulticastDomains`
1. `DescribeTrunkInterfaceAssociations`
1. `DescribeTransitGateways`
1. `DescribeBundleTasks`
1. `DescribeStoreImageTasks`
1. `DescribeRouteTables`
1. `DescribeVpcEncryptionControls`
1. `DescribeTrafficMirrorFilters`
1. `DescribeTransitGatewayPeeringAttachments`
1. `DescribeRouteServerEndpoints`
1. `DescribeSpotFleetRequests`
1. `DescribeCapacityBlockStatus`
1. `DescribeVpcBlockPublicAccessOptions`
1. `DescribeRouteServers`
1. `DescribeKeyPairs`
1. `DescribeSpotPriceHistory`
1. `DescribeAwsNetworkPerformanceMetricSubscriptions`
1. `DescribeExportTasks`
1. `DescribeTransitGatewayMeteringPolicies`
1. `DescribeOutpostLags`
1. `DescribePlacementGroups`
1. `DescribeFastLaunchImages`
1. `DescribeTrafficMirrorTargets`
1. `DescribeNetworkAcls`
1. `DescribeTransitGatewayConnects`
1. `GetAllowedImagesSettings`
1. `DescribeCustomerGateways`
1. `DescribeImageUsageReportEntries`
1. `DescribeVpcPeeringConnections`
1. `GetInstanceMetadataDefaults`
1. `DescribeSecurityGroupVpcAssociations`
1. `DescribeInstanceEventWindows`
1. `DescribeAddressTransfers`
1. `DescribeVpnGateways`
1. `DescribeCoipPools`
1. `DescribeNetworkInterfacePermissions`
1. `DescribeLocalGatewayRouteTableVpcAssociations`
1. `DescribeConversionTasks`
1. `DescribeNetworkInsightsAccessScopes`
1. `DescribeIpv6Pools`
1. `DescribeTransitGatewayAttachments`
1. `DescribeImportSnapshotTasks`
1. `DescribeTransitGatewayPolicyTables`
1. `GetVpnConnectionDeviceTypes`
1. `DescribeInstances`
1. `DescribeInternetGateways`
1. `DescribeCarrierGateways`
1. `DescribeAddressesAttribute`
1. `DescribeLocalGateways`
1. `DescribeIpamByoasn`
1. `DescribeInstanceTypeOfferings`
1. `DescribeTransitGatewayConnectPeers`
1. `DescribeIamInstanceProfileAssociations`
1. `DescribeVpnConcentrators`
1. `DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations`
1. `DescribeDhcpOptions`
1. `DescribeTags`
1. `DescribeAggregateIdFormat`
1. `DescribeSpotDatafeedSubscription`
1. `DescribePrincipalIdFormat`
1. `DescribePrefixLists`
1. `DescribeVpcClassicLink`
1. `DescribeMacHosts`
1. `DescribeEgressOnlyInternetGateways`
1. `DescribeRegions`
1. `DescribeVpcClassicLinkDnsSupport`
1. `GetEnabledIpamPolicy`
1. `DescribeVerifiedAccessInstanceLoggingConfigurations`
1. `DescribeInstanceCreditSpecifications`
1. `DescribeInstanceEventNotificationAttributes`
1. `GetImageBlockPublicAccessState`
1. `GetEbsEncryptionByDefault`
1. `DescribeMovingAddresses`
1. `GetSerialConsoleAccessStatus`
1. `DescribeVpcEndpointServices`
1. `DescribeAccountAttributes`
1. `GetCapacityManagerAttributes`

### Dependent Operations:
1. `GetLaunchTemplateData`
1. `DescribeClientVpnConnections`
1. `GetCapacityManagerMetricDimensions`
1. `GetActiveVpnTunnelStatus`
1. `GetIpamResourceCidrs`
1. `DescribeImageAttribute`
1. `GetDeclarativePoliciesReportSummary`
1. `GetRouteServerRoutingDatabase`
1. `DescribeCapacityBlockOfferings`
1. `DescribeScheduledInstanceAvailability`
1. `GetIpamPrefixListResolverRules`
1. `GetIpamPoolCidrs`
1. `GetIpamAddressHistory`
1. `GetAssociatedEnclaveCertificateIamRoles`
1. `GetIpamDiscoveredResourceCidrs`
1. `DescribeClientVpnRoutes`
1. `DescribeCapacityReservationBillingRequests`
1. `DescribeStaleSecurityGroups`
1. `GetVpnTunnelReplacementStatus`
1. `DescribeVpcEndpointServicePermissions`
1. `GetTransitGatewayMeteringPolicyEntries`
1. `DescribeSnapshotAttribute`
1. `GetTransitGatewayPrefixListReferences`
1. `GetHostReservationPurchasePreview`
1. `DescribeClientVpnTargetNetworks`
1. `DescribeByoipCidrs`
1. `GetSecurityGroupsForVpc`
1. `DescribeFleetHistory`
1. `GetIpamPoolAllocations`
1. `GetCoipPoolUsage`
1. `DescribeSecurityGroupReferences`
1. `GetNetworkInsightsAccessScopeAnalysisFindings`
1. `GetVpcResourcesBlockingEncryptionEnforcement`
1. `GetSpotPlacementScores`
1. `GetCapacityManagerMetricData`
1. `GetVerifiedAccessEndpointTargets`
1. `GetTransitGatewayPolicyTableEntries`
1. `GetNetworkInsightsAccessScopeContent`
1. `GetAssociatedIpv6PoolCidrs`
1. `GetReservedInstancesExchangeQuote`
1. `GetCapacityReservationUsage`
1. `DescribeNetworkInterfaceAttribute`
1. `DescribeClientVpnAuthorizationRules`
1. `DescribeFleetInstances`
1. `GetSubnetCidrReservations`
1. `GetImageAncestry`
1. `DescribeFpgaImageAttribute`
1. `DescribeVolumeAttribute`
1. `GetIpamPolicyAllocationRules`
1. `GetGroupsForCapacityReservation`
1. `DescribeVpcAttribute`
1. `GetTransitGatewayMulticastDomainAssociations`
1. `GetIpamPolicyOrganizationTargets`
1. `GetConsoleScreenshot`
1. `GetFlowLogsIntegrationTemplate`
