# EC2 - Resource Inventory Report

**Generated:** 2026-01-20T19:24:28.770894

**Root Operations:** DescribeAccountAttributes, DescribeAddressTransfers, DescribeAddresses, DescribeAddressesAttribute, DescribeAggregateIdFormat, DescribeAvailabilityZones, DescribeAwsNetworkPerformanceMetricSubscriptions, DescribeBundleTasks, DescribeCapacityBlockExtensionHistory, DescribeCapacityBlockStatus, DescribeCapacityBlocks, DescribeCapacityManagerDataExports, DescribeCapacityReservationFleets, DescribeCapacityReservationTopology, DescribeCapacityReservations, DescribeCarrierGateways, DescribeClassicLinkInstances, DescribeClientVpnEndpoints, DescribeCoipPools, DescribeConversionTasks, DescribeCustomerGateways, DescribeDeclarativePoliciesReports, DescribeDhcpOptions, DescribeEgressOnlyInternetGateways, DescribeElasticGpus, DescribeExportImageTasks, DescribeExportTasks, DescribeFastLaunchImages, DescribeFastSnapshotRestores, DescribeFleets, DescribeFlowLogs, DescribeFpgaImages, DescribeHostReservationOfferings, DescribeHostReservations, DescribeHosts, DescribeIamInstanceProfileAssociations, DescribeIdFormat, DescribeImageUsageReportEntries, DescribeImageUsageReports, DescribeImages, DescribeImportImageTasks, DescribeImportSnapshotTasks, DescribeInstanceConnectEndpoints, DescribeInstanceCreditSpecifications, DescribeInstanceEventNotificationAttributes, DescribeInstanceEventWindows, DescribeInstanceImageMetadata, DescribeInstanceSqlHaHistoryStates, DescribeInstanceSqlHaStates, DescribeInstanceStatus, DescribeInstanceTopology, DescribeInstanceTypeOfferings, DescribeInstanceTypes, DescribeInstances, DescribeInternetGateways, DescribeIpamByoasn, DescribeIpamExternalResourceVerificationTokens, DescribeIpamPolicies, DescribeIpamPools, DescribeIpamPrefixListResolverTargets, DescribeIpamPrefixListResolvers, DescribeIpamResourceDiscoveries, DescribeIpamResourceDiscoveryAssociations, DescribeIpamScopes, DescribeIpams, DescribeIpv6Pools, DescribeKeyPairs, DescribeLaunchTemplateVersions, DescribeLaunchTemplates, DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations, DescribeLocalGatewayRouteTableVpcAssociations, DescribeLocalGatewayRouteTables, DescribeLocalGatewayVirtualInterfaceGroups, DescribeLocalGatewayVirtualInterfaces, DescribeLocalGateways, DescribeLockedSnapshots, DescribeMacHosts, DescribeMacModificationTasks, DescribeManagedPrefixLists, DescribeMovingAddresses, DescribeNatGateways, DescribeNetworkAcls, DescribeNetworkInsightsAccessScopeAnalyses, DescribeNetworkInsightsAccessScopes, DescribeNetworkInsightsAnalyses, DescribeNetworkInsightsPaths, DescribeNetworkInterfacePermissions, DescribeNetworkInterfaces, DescribeOutpostLags, DescribePlacementGroups, DescribePrefixLists, DescribePrincipalIdFormat, DescribePublicIpv4Pools, DescribeRegions, DescribeReplaceRootVolumeTasks, DescribeReservedInstances, DescribeReservedInstancesListings, DescribeReservedInstancesModifications, DescribeReservedInstancesOfferings, DescribeRouteServerEndpoints, DescribeRouteServerPeers, DescribeRouteServers, DescribeRouteTables, DescribeScheduledInstances, DescribeSecurityGroupRules, DescribeSecurityGroupVpcAssociations, DescribeSecurityGroups, DescribeServiceLinkVirtualInterfaces, DescribeSnapshotTierStatus, DescribeSnapshots, DescribeSpotDatafeedSubscription, DescribeSpotFleetRequests, DescribeSpotInstanceRequests, DescribeSpotPriceHistory, DescribeStoreImageTasks, DescribeSubnets, DescribeTags, DescribeTrafficMirrorFilterRules, DescribeTrafficMirrorFilters, DescribeTrafficMirrorSessions, DescribeTrafficMirrorTargets, DescribeTransitGatewayAttachments, DescribeTransitGatewayConnectPeers, DescribeTransitGatewayConnects, DescribeTransitGatewayMeteringPolicies, DescribeTransitGatewayMulticastDomains, DescribeTransitGatewayPeeringAttachments, DescribeTransitGatewayPolicyTables, DescribeTransitGatewayRouteTableAnnouncements, DescribeTransitGatewayRouteTables, DescribeTransitGatewayVpcAttachments, DescribeTransitGateways, DescribeTrunkInterfaceAssociations, DescribeVerifiedAccessEndpoints, DescribeVerifiedAccessGroups, DescribeVerifiedAccessInstanceLoggingConfigurations, DescribeVerifiedAccessInstances, DescribeVerifiedAccessTrustProviders, DescribeVolumeStatus, DescribeVolumes, DescribeVolumesModifications, DescribeVpcBlockPublicAccessExclusions, DescribeVpcBlockPublicAccessOptions, DescribeVpcClassicLink, DescribeVpcClassicLinkDnsSupport, DescribeVpcEncryptionControls, DescribeVpcEndpointAssociations, DescribeVpcEndpointConnectionNotifications, DescribeVpcEndpointConnections, DescribeVpcEndpointServiceConfigurations, DescribeVpcEndpointServices, DescribeVpcEndpoints, DescribeVpcPeeringConnections, DescribeVpcs, DescribeVpnConcentrators, DescribeVpnConnections, DescribeVpnGateways, GetAllowedImagesSettings, GetAwsNetworkPerformanceData, GetCapacityManagerAttributes, GetEbsDefaultKmsKeyId, GetEbsEncryptionByDefault, GetEnabledIpamPolicy, GetImageBlockPublicAccessState, GetInstanceMetadataDefaults, GetSerialConsoleAccessStatus, GetSnapshotBlockPublicAccessState, GetVpnConnectionDeviceTypes, ListImagesInRecycleBin, ListSnapshotsInRecycleBin, ListVolumesInRecycleBin

---

## Primary Resource

### associated_rol_associated_role

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.associated_rol_associated_role_arn`

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetAssociatedEnclaveCertificateIamRoles`

---

### capacity_reservation_capacity_reservation

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.capacity_reservation_capacity_reservation_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityReservations`

---

### capacity_reservation_fleet_capacity_reservation_fleet

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.capacity_reservation_fleet_capacity_reservation_fleet_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityReservationFleets`
- `DescribeCapacityReservationFleets`
- `DescribeCapacityReservations`

---

### capacity_reservation_outpost

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.capacity_reservation_outpost_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityReservations`
- `DescribeHosts`
- `DescribeInstanceStatus`
- `DescribeLocalGatewayRouteTables`
- `DescribeLocalGateways`
- `DescribeNetworkInterfaces`
- `DescribeOutpostLags`
- `DescribeServiceLinkVirtualInterfaces`
- `DescribeSnapshots`
- `DescribeSubnets`
- `DescribeVolumeStatus`
- `DescribeVolumes`
- `ListVolumesInRecycleBin`

---

### capacity_reservation_placement_group

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.capacity_reservation_placement_group_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityReservations`

---

### certificate

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.certificate_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeClientVpnEndpoints`

---

### client_vpn_endpoint_server_certificate

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.client_vpn_endpoint_server_certificate_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeClientVpnEndpoints`

---

### coip_pool_pool

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.coip_pool_pool_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeCoipPools`
- `DescribeCoipPools`
- `DescribeIpv6Pools`
- `DescribePublicIpv4Pools`

---

### connection_notification_set_connection_notification

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.connection_notification_set_connection_notification_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpointConnectionNotifications`
- `DescribeVpcEndpointConnectionNotifications`

---

### customer_gateway_certificate

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.customer_gateway_certificate_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeCustomerGateways`

---

### instance_connect_endpoint

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.instance_connect_endpoint_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeInstanceConnectEndpoints`

---

### instance_connect_endpoint_instance_connect_endpoint

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.instance_connect_endpoint_instance_connect_endpoint_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeInstanceConnectEndpoints`
- `DescribeInstanceConnectEndpoints`

---

### ipam

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamExternalResourceVerificationTokens`

---

### ipam_discovery_association

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_resource_discovery_association_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamResourceDiscoveryAssociations`

---

### ipam_discovery_association_ipam_discovery_association

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_resource_discovery_association_ipam_resource_discovery_association_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamResourceDiscoveryAssociations`

---

### ipam_discovery_ipam_discovery

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_resource_discovery_ipam_resource_discovery_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamResourceDiscoveries`

---

### ipam_external_verification_token_ipam

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_external_resource_verification_token_ipam_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamExternalResourceVerificationTokens`
- `DescribeIpamPools`
- `DescribeIpamPrefixListResolvers`
- `DescribeIpamResourceDiscoveryAssociations`
- `DescribeIpamScopes`
- `DescribeIpams`

---

### ipam_external_verification_token_ipam_external_verification_token

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_external_resource_verification_token_ipam_external_resource_verification_token_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamExternalResourceVerificationTokens`

---

### ipam_policy_ipam_policy

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_policy_ipam_policy_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamPolicies`
- `DescribeIpamPolicies`
- `GetEnabledIpamPolicy`

---

### ipam_pool_ipam_pool

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_pool_ipam_pool_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamPools`
- `DescribeIpamPools`

---

### ipam_pool_ipam_scope

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_pool_ipam_scope_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamPools`
- `DescribeIpamScopes`

---

### ipam_prefix_list_resolver_ipam_prefix_list_resolver

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_prefix_list_resolver_ipam_prefix_list_resolver_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamPrefixListResolvers`

---

### ipam_prefix_list_resolver_target

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_prefix_list_resolver_target_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamPrefixListResolverTargets`

---

### ipam_prefix_list_resolver_target_ipam_prefix_list_resolver_target

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.ipam_prefix_list_resolver_target_ipam_prefix_list_resolver_target_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamPrefixListResolverTargets`
- `DescribeIpamPrefixListResolverTargets`
- `DescribeManagedPrefixLists`

---

### launch_permission_organization

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.launch_permission_organization_arn`

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `DescribeImageAttribute`

---

### launch_permission_organizational_unit

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.launch_permission_organizational_unit_arn`

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `DescribeImageAttribute`

---

### local_gateway_route_table_vpc_association_local_gateway_route_table

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.local_gateway_route_table_vpc_association_local_gateway_route_table_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeLocalGatewayRouteTableVpcAssociations`

---

### local_gateway_virtual_interfac_local_gateway_virtual_interface

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.local_gateway_virtual_interfac_local_gateway_virtual_interface_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeLocalGatewayVirtualInterfaces`
- `DescribeLocalGatewayVirtualInterfaces`

---

### local_gateway_virtual_interface_group

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.local_gateway_virtual_interface_group_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeLocalGatewayVirtualInterfaceGroups`

---

### local_gateway_virtual_interface_group_local_gateway_virtual_interface_group

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.local_gateway_virtual_interface_group_local_gateway_virtual_interface_group_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeLocalGatewayVirtualInterfaceGroups`

---

### metric_dimension_result_reservation

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.metric_dimension_result_reservation_arn`

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetCapacityManagerMetricDimensions`

---

### network_insights_access_scop_network_insights_access_scope

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.network_insights_access_scop_network_insights_access_scope_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInsightsAccessScopes`

---

### network_insights_access_scope_analys_network_insights_access_scope_analysis

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.network_insights_access_scope_analys_network_insights_access_scope_analysis_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInsightsAccessScopeAnalyses`
- `DescribeNetworkInsightsAccessScopeAnalyses`

---

### network_insights_analys_filter_ins

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.network_insights_analys_filter_in_arns`

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInsightsAnalyses`

---

### network_insights_analys_filter_outs

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.network_insights_analys_filter_out_arns`

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInsightsAnalyses`

---

### network_insights_analys_network_insights_analysis

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.network_insights_analys_network_insights_analysis_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInsightsAnalyses`
- `DescribeNetworkInsightsAnalyses`

---

### network_insights_path

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.network_insights_path_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInsightsPaths`

---

### network_insights_path_destination

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.network_insights_path_destination_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInsightsPaths`

---

### network_insights_path_network_insights_path

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.network_insights_path_network_insights_path_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInsightsPaths`

---

### network_insights_path_source

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.network_insights_path_source_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInsightsPaths`

---

### placement_group_group

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.placement_group_group_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribePlacementGroups`
- `DescribePlacementGroups`
- `DescribeSecurityGroupRules`
- `DescribeSecurityGroupVpcAssociations`
- `DescribeSecurityGroups`

---

### prefix_list_prefix_list

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.prefix_list_prefix_list_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeManagedPrefixLists`
- `DescribeManagedPrefixLists`
- `DescribePrefixLists`

---

### principal

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.principal_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribePrincipalIdFormat`

---

### security_group_security_group

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.security_group_security_group_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeSecurityGroups`

---

### service_link_virtual_interfac_service_link_virtual_interface

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.service_link_virtual_interfac_service_link_virtual_interface_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeServiceLinkVirtualInterfaces`
- `DescribeServiceLinkVirtualInterfaces`

---

### subnet_subnet

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.subnet_subnet_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeSubnets`

---

### traffic_mirror_target_network_load_balancer

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.traffic_mirror_target_network_load_balancer_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeTrafficMirrorTargets`

---

### transit_gateway

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.transit_gateway_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGateways`

---

### transit_gateway_multicast_domain

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.transit_gateway_multicast_domain_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayMulticastDomains`

---

### transit_gateway_multicast_domain_transit_gateway_multicast_domain

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.transit_gateway_multicast_domain_transit_gateway_multicast_domain_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayMulticastDomains`
- `DescribeTransitGatewayMulticastDomains`

---

### transit_gateway_transit_gateway

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.transit_gateway_transit_gateway_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGateways`

---

### verified_access_endpoint_domain_certificate

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.verified_access_endpoint_domain_certificate_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVerifiedAccessEndpoints`

---

### verified_access_group

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.verified_access_group_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVerifiedAccessGroups`

---

### verified_access_group_verified_access_group

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.verified_access_group_verified_access_group_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVerifiedAccessGroups`

---

### vpc_block_public_access_exclusion_resource

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.vpc_block_public_access_exclusion_resource_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcBlockPublicAccessExclusions`

---

### vpc_endpoint_association_associated_resource

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.vpc_endpoint_association_associated_resource_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpointAssociations`

---

### vpc_endpoint_association_configuration_group

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.vpc_endpoint_association_resource_configuration_group_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpointAssociations`

---

### vpc_endpoint_association_service_network

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.vpc_endpoint_association_service_network_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpointAssociations`
- `DescribeVpcEndpointAssociations`
- `DescribeVpcEndpoints`

---

### vpc_endpoint_connection_gateway_load_balancers

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.vpc_endpoint_connection_gateway_load_balancer_arns`

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpointConnections`
- `DescribeVpcEndpointServiceConfigurations`

---

### vpc_endpoint_connection_network_load_balancers

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.vpc_endpoint_connection_network_load_balancer_arns`

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpointConnections`
- `DescribeVpcEndpointServiceConfigurations`

---

### vpn_connection_core_network

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.vpn_connection_core_network_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVpnConnections`

---

### vpn_connection_core_network_attachment

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.vpn_connection_core_network_attachment_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVpnConnections`

---

### vpn_connection_pre_shared_key

- **Status:** ✅ **INVENTORY** 
- **Classification:** PRIMARY_RESOURCE
- **Has ARN:** Yes
- **ARN Entity:** `ec2.vpn_connection_pre_shared_key_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVpnConnections`

---

## Configuration

### allowed_principal_service_permission

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** CONFIGURATION
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `DescribeVpcEndpointServicePermissions`

---

### flow_log_deliver_logs_permission

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** CONFIGURATION
- **Has ARN:** Yes
- **ARN Entity:** `ec2.flow_log_deliver_logs_permission_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeFlowLogs`

---

### network_acl_network_acl

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** CONFIGURATION
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkAcls`

---

### network_interface_permission_network_interface_permission

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** CONFIGURATION
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInterfacePermissions`

---

### route_server_sns_topic

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** CONFIGURATION
- **Has ARN:** Yes
- **ARN Entity:** `ec2.route_server_sns_topic_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeRouteServers`

---

### security_group_rul_security_group_rule

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** CONFIGURATION
- **Has ARN:** Yes
- **ARN Entity:** `ec2.security_group_rul_security_group_rule_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeSecurityGroupRules`
- `DescribeSecurityGroupRules`

---

### traffic_mirror_filter_rul_traffic_mirror_filter_rule

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** CONFIGURATION
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTrafficMirrorFilterRules`

---

### vpc_endpoint_configuration

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** CONFIGURATION
- **Has ARN:** Yes
- **ARN Entity:** `ec2.vpc_endpoint_resource_configuration_arn`

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpoints`

---

## Ephemeral

### analysis_finding_finding

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetNetworkInsightsAccessScopeAnalysisFindings`

---

### conversion_task_conversion_task

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeConversionTasks`

---

### export_image_task_export_image_task

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeExportImageTasks`

---

### export_task_export_task

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeExportTasks`

---

### import_image_task_import_task

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeImportImageTasks`
- `DescribeImportSnapshotTasks`

---

### mac_modification_task

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeMacModificationTasks`

---

### mac_modification_task_mac_modification_task

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeMacModificationTasks`

---

### replace_root_volume_task_replace_root_volume_task

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeReplaceRootVolumeTasks`

---

### spot_fleet_request_config_spot_fleet_request

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeSpotFleetRequests`

---

### spot_instance_request_spot_instance_request

- **Status:** ❌ Not in inventory 
- **Classification:** EPHEMERAL
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeSpotInstanceRequests`

---

## Sub Resource

### account_attribut_attribute

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeAccountAttributes`

---

### address_association

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeAddresses`
- `DescribeIamInstanceProfileAssociations`
- `DescribeTrunkInterfaceAssociations`

---

### address_instance

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeAddresses`
- `DescribeBundleTasks`
- `DescribeClassicLinkInstances`
- `DescribeElasticGpus`
- `DescribeIamInstanceProfileAssociations`
- `DescribeInstanceCreditSpecifications`
- `DescribeInstanceImageMetadata`
- `DescribeInstanceSqlHaHistoryStates`
- `DescribeInstanceSqlHaStates`
- `DescribeInstanceStatus`
- `DescribeInstanceTopology`
- `DescribeMacModificationTasks`
- `DescribeReplaceRootVolumeTasks`
- `DescribeSpotInstanceRequests`

---

### address_network_interface_owner

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeAddresses`

---

### address_transfer_allocation

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeAddressTransfers`
- `DescribeAddresses`
- `DescribeAddressesAttribute`

---

### address_transfer_transfer_account

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeAddressTransfers`

---

### associated_rol_certificate_s3_bucket

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetAssociatedEnclaveCertificateIamRoles`

---

### associated_rol_encryption_kms_key

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetAssociatedEnclaveCertificateIamRoles`

---

### availability_zon_group

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeAvailabilityZones`
- `DescribeCapacityReservationTopology`
- `DescribeInstanceTopology`
- `DescribePlacementGroups`
- `DescribeSecurityGroups`

---

### availability_zon_group_long

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeAvailabilityZones`

---

### availability_zon_parent_zone

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeAvailabilityZones`

---

### availability_zon_region

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeAvailabilityZones`
- `DescribeRegions`

---

### availability_zon_zone

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeAvailabilityZones`
- `DescribeInstanceImageMetadata`
- `DescribeInstanceTopology`

---

### bundle

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeBundleTasks`

---

### bundle_task_bundle

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeBundleTasks`

---

### byoasn_ipam

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamByoasn`
- `DescribeIpamExternalResourceVerificationTokens`
- `DescribeIpamPolicies`
- `DescribeIpamResourceDiscoveryAssociations`
- `DescribeIpams`

---

### capacity_block

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityBlockStatus`

---

### capacity_block_extension_availability_zone

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityBlockExtensionHistory`
- `DescribeCapacityBlocks`
- `DescribeCapacityReservationTopology`
- `DescribeCapacityReservations`
- `DescribeFastSnapshotRestores`
- `DescribeHosts`
- `DescribeInstanceConnectEndpoints`
- `DescribeInstanceStatus`
- `DescribeNetworkInterfaces`
- `DescribeReservedInstances`
- `DescribeReservedInstancesOfferings`
- `DescribeSpotPriceHistory`
- `DescribeSubnets`
- `DescribeVolumeStatus`
- `DescribeVolumes`
- `ListVolumesInRecycleBin`

---

### capacity_block_extension_capacity_block_extension_offering

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityBlockExtensionHistory`

---

### capacity_block_extension_capacity_reservation

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityBlockExtensionHistory`
- `DescribeCapacityReservationTopology`
- `DescribeCapacityReservations`

---

### capacity_block_offering_capacity_block_offering

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `DescribeCapacityBlockOfferings`

---

### capacity_block_status_capacity_block

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityBlockStatus`
- `DescribeCapacityBlocks`
- `DescribeCapacityReservationTopology`
- `DescribeCapacityReservations`
- `DescribeInstanceTopology`

---

### capacity_manager_data_export_capacity_manager_data_export

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityManagerDataExports`

---

### capacity_manager_data_export_s3_bucket

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityManagerDataExports`

---

### capacity_reservation_unused_reservation_billing_owner

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCapacityReservations`

---

### carrier_gateway_carrier_gateway

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCarrierGateways`

---

### carrier_gateway_vpc

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCarrierGateways`
- `DescribeClassicLinkInstances`
- `DescribeClientVpnEndpoints`
- `DescribeInstanceConnectEndpoints`
- `DescribeLocalGatewayRouteTableVpcAssociations`
- `DescribeNatGateways`
- `DescribeNetworkAcls`
- `DescribeNetworkInterfaces`
- `DescribeRouteServerEndpoints`
- `DescribeRouteServerPeers`
- `DescribeRouteTables`
- `DescribeSecurityGroupVpcAssociations`
- `DescribeSecurityGroups`
- `DescribeSubnets`
- `DescribeTransitGatewayVpcAttachments`
- `DescribeVpcClassicLink`
- `DescribeVpcClassicLinkDnsSupport`
- `DescribeVpcEncryptionControls`
- `DescribeVpcEndpoints`
- `DescribeVpcs`

---

### client_vpn_endpoint_client_vpn_endpoint

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeClientVpnEndpoints`

---

### client_vpn_endpoint_dns

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeClientVpnEndpoints`
- `DescribeInstanceConnectEndpoints`

---

### client_vpn_target_network_target_network

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `DescribeClientVpnTargetNetworks`

---

### coip_address_usag_aws_account

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetCoipPoolUsage`

---

### coip_pool_local_gateway_route_table

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCoipPools`

---

### connection_common

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `DescribeClientVpnConnections`

---

### connection_connection

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `DescribeClientVpnConnections`

---

### connection_notification_set_service

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpointConnectionNotifications`
- `DescribeVpcEndpointConnections`
- `DescribeVpcEndpointServiceConfigurations`

---

### customer_gateway_customer_gateway

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCustomerGateways`
- `DescribeVpnConnections`

---

### customer_gateway_device

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeCustomerGateways`

---

### dhcp_option_dhcp_options

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeDhcpOptions`
- `DescribeVpcs`

---

### egress_only_internet_gateway_egress_only_internet_gateway

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeEgressOnlyInternetGateways`

---

### elastic_gpu_set_elastic_gpu

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeElasticGpus`

---

### exclusion

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcBlockPublicAccessExclusions`

---

### export_image_task_image

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeExportImageTasks`
- `DescribeFastLaunchImages`
- `DescribeImageUsageReportEntries`
- `DescribeImageUsageReports`
- `DescribeImages`
- `DescribeImportImageTasks`
- `DescribeReplaceRootVolumeTasks`
- `ListImagesInRecycleBin`

---

### fast_snapshot_restor_snapshot

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeFastSnapshotRestores`
- `DescribeLockedSnapshots`
- `DescribeReplaceRootVolumeTasks`
- `DescribeSnapshotTierStatus`
- `DescribeSnapshots`
- `DescribeVolumes`
- `ListSnapshotsInRecycleBin`
- `ListVolumesInRecycleBin`

---

### fleet_fleet

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeFleets`

---

### flow_log_flow_log

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeFlowLogs`

---

### flow_log_log_group

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeFlowLogs`

---

### fpga_imag

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeFpgaImages`
- `DescribeImages`
- `DescribeInstanceEventWindows`
- `ListImagesInRecycleBin`

---

### fpga_imag_fpga_image

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeFpgaImages`

---

### fpga_imag_fpga_image_global

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeFpgaImages`

---

### fpga_imag_pci

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeFpgaImages`

---

### group

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations`

---

### history_record_resource

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetIpamAddressHistory`
- `GetIpamResourceCidrs`

---

### host_asset

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeHosts`

---

### host_host

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeHosts`
- `DescribeMacHosts`

---

### host_reservation_set_host_reservation

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeHostReservations`
- `DescribeHosts`

---

### imag_kernel

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeImages`

---

### imag_ramdisk

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeImages`

---

### imag_root_device

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeImages`

---

### imag_source_image

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeImages`

---

### imag_source_instance

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeImages`

---

### image_usage_report_entry_account

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeImageUsageReportEntries`

---

### import_image_task_kms_key

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeImportImageTasks`
- `DescribeSnapshots`
- `DescribeVolumes`
- `GetEbsDefaultKmsKeyId`

---

### instance_connect_endpoint_fips_dns

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeInstanceConnectEndpoints`

---

### instance_event_window_instance_event_window

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeInstanceEventWindows`

---

### interface_association_branch_interface

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTrunkInterfaceAssociations`

---

### interface_association_trunk_interface

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTrunkInterfaceAssociations`

---

### interface_association_vlan

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTrunkInterfaceAssociations`

---

### internet_gateway_internet_gateway

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeInternetGateways`

---

### ipam_default_resource_discovery

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpams`

---

### ipam_default_resource_discovery_association

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpams`

---

### ipam_discovered_account_organizational_unit

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetIpamDiscoveredAccounts`

---

### ipam_discovered_public_address_address_allocation

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetIpamDiscoveredPublicAddresses`

---

### ipam_discovered_public_address_address_owner

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetIpamDiscoveredPublicAddresses`

---

### ipam_discovered_public_address_public_ipv4_pool

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetIpamDiscoveredPublicAddresses`

---

### ipam_external_resource_verification_token_ipam_external_resource_verification_token

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamExternalResourceVerificationTokens`

---

### ipam_external_resource_verification_token_token

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamExternalResourceVerificationTokens`

---

### ipam_pool_allocation_ipam_pool_allocation

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetIpamPoolAllocations`

---

### ipam_pool_cidr_ipam_pool_cidr

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetIpamPoolCidrs`

---

### ipam_pool_source_ipam_pool

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamPools`

---

### ipam_prefix_list_resolver_target_ipam_prefix_list_resolver

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamPrefixListResolverTargets`
- `DescribeIpamPrefixListResolvers`

---

### ipam_private_default_scope

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpams`

---

### ipam_public_default_scope

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpams`

---

### ipam_resource_discovery_association_ipam_resource_discovery_association

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamResourceDiscoveryAssociations`

---

### ipam_resource_discovery_ipam_resource_discovery

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamResourceDiscoveries`
- `DescribeIpamResourceDiscoveryAssociations`

---

### ipam_scop_ipam_scope

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeIpamScopes`

---

### key

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeKeyPairs`

---

### key_pair_key

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeKeyPairs`

---

### key_pair_key_pair

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeKeyPairs`

---

### launch_permission_user

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `DescribeImageAttribute`

---

### launch_template

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeLaunchTemplateVersions`

---

### launch_template_data_ram_disk

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetLaunchTemplateData`

---

### launch_template_version_launch_template

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeLaunchTemplateVersions`
- `DescribeLaunchTemplates`

---

### local_gateway_route_table_virtual_interface_group_association_local_gateway

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations`
- `DescribeLocalGatewayRouteTableVpcAssociations`
- `DescribeLocalGatewayRouteTables`
- `DescribeLocalGatewayVirtualInterfaceGroups`
- `DescribeLocalGatewayVirtualInterfaces`
- `DescribeLocalGateways`

---

### local_gateway_route_table_virtual_interface_group_association_local_gateway_route_table_virtual_interface_group_association

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations`

---

### local_gateway_route_table_vpc_association_local_gateway_route_table_vpc_association

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeLocalGatewayRouteTableVpcAssociations`

---

### local_gateway_virtual_interfac_outpost_lag

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeLocalGatewayVirtualInterfaces`
- `DescribeOutpostLags`
- `DescribeServiceLinkVirtualInterfaces`

---

### mac_host_host

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeMacHosts`

---

### nat_gateway_nat_gateway

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeNatGateways`

---

### nat_gateway_route_table

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeNatGateways`
- `DescribeRouteTables`

---

### network_insights_access_scope_analys_network_insights_access_scope

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInsightsAccessScopeAnalyses`
- `DescribeNetworkInsightsAccessScopes`

---

### network_insights_analys_network_insights_path

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInsightsAnalyses`
- `DescribeNetworkInsightsPaths`

---

### network_interfac_private_dns

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInterfaces`
- `DescribeVpcEndpointServiceConfigurations`

---

### network_interfac_public_dns

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInterfaces`

---

### network_interface_permission_aws_account

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeNetworkInterfacePermissions`
- `DescribeVpcBlockPublicAccessOptions`

---

### offering_set_offering

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeHostReservationOfferings`
- `DescribeHostReservations`

---

### organization_target_organization_target

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetIpamPolicyOrganizationTargets`

---

### outpost_lag

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeOutpostLags`

---

### product_cod_product_code

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `DescribeSnapshotAttribute`
- `DescribeVolumeAttribute`

---

### report_report

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeDeclarativePoliciesReports`
- `DescribeImageUsageReportEntries`
- `DescribeImageUsageReports`

---

### report_target

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeDeclarativePoliciesReports`

---

### reservation_requester

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeInstances`
- `DescribeNetworkInterfaces`

---

### reservation_reservation

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeInstances`

---

### reserved_instanc_reserved_instances

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeReservedInstances`
- `DescribeReservedInstancesListings`

---

### reserved_instance_value_set_reserved_instance

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetReservedInstancesExchangeQuote`

---

### reserved_instances_listing_reserved_instances_listing

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeReservedInstancesListings`

---

### reserved_instances_modification_reserved_instances_modification

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeReservedInstancesModifications`

---

### reserved_instances_offering_reserved_instances_offering

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeReservedInstancesOfferings`

---

### route_server_endpoint_eni

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeRouteServerEndpoints`

---

### route_server_endpoint_route_server

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeRouteServerEndpoints`
- `DescribeRouteServerPeers`
- `DescribeRouteServers`

---

### route_server_endpoint_route_server_endpoint

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeRouteServerEndpoints`
- `DescribeRouteServerPeers`

---

### route_server_peer_endpoint_eni

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeRouteServerPeers`

---

### route_server_peer_route_server_peer

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeRouteServerPeers`

---

### scheduled_instance_set_scheduled_instance

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeScheduledInstances`

---

### security_group_for_vpc_primary_vpc

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetSecurityGroupsForVpc`

---

### security_group_reference_set_referencing_vpc

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `DescribeSecurityGroupReferences`

---

### security_group_rul_group_owner

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeSecurityGroupRules`
- `DescribeSecurityGroupVpcAssociations`

---

### security_group_vpc_association_vpc_owner

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeSecurityGroupVpcAssociations`
- `DescribeTransitGatewayVpcAttachments`

---

### service_configuration_service

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpointServiceConfigurations`
- `DescribeVpcEndpoints`

---

### service_link_virtual_interfac_outpost

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeServiceLinkVirtualInterfaces`

---

### snapshot_data_encryption_key

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeSnapshots`

---

### snapshot_tier_status_volume

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeSnapshotTierStatus`
- `DescribeSnapshots`
- `DescribeVolumeStatus`
- `DescribeVolumes`
- `DescribeVolumesModifications`
- `ListSnapshotsInRecycleBin`
- `ListVolumesInRecycleBin`

---

### spot_instance_request_launched_availability_zone

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeSpotInstanceRequests`

---

### store_image_task_result_ami

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeStoreImageTasks`

---

### subnet_ipv4_cidr_reservation_subnet_cidr_reservation

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetSubnetCidrReservations`

---

### traffic_mirror_filter

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTrafficMirrorFilterRules`

---

### traffic_mirror_filter_rul_traffic_mirror_filter

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTrafficMirrorFilterRules`
- `DescribeTrafficMirrorFilters`
- `DescribeTrafficMirrorSessions`

---

### traffic_mirror_session_traffic_mirror_session

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTrafficMirrorSessions`

---

### traffic_mirror_session_traffic_mirror_target

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTrafficMirrorSessions`
- `DescribeTrafficMirrorTargets`

---

### traffic_mirror_session_virtual_network

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTrafficMirrorSessions`

---

### traffic_mirror_target_gateway_load_balancer_endpoint

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTrafficMirrorTargets`

---

### transit_gateway_attachment_transit_gateway

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayAttachments`
- `DescribeTransitGatewayConnects`
- `DescribeTransitGatewayMeteringPolicies`
- `DescribeTransitGatewayMulticastDomains`
- `DescribeTransitGatewayPolicyTables`
- `DescribeTransitGatewayRouteTableAnnouncements`
- `DescribeTransitGatewayRouteTables`
- `DescribeTransitGatewayVpcAttachments`
- `DescribeTransitGateways`
- `DescribeVpnConcentrators`
- `DescribeVpnConnections`

---

### transit_gateway_attachment_transit_gateway_owner

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayAttachments`

---

### transit_gateway_connect_peer_transit_gateway_connect_peer

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayConnectPeers`

---

### transit_gateway_connect_transport_transit_gateway_attachment

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayConnects`

---

### transit_gateway_metering_policy_transit_gateway_metering_policy

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayMeteringPolicies`

---

### transit_gateway_peering_attachment_accepter_transit_gateway_attachment

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayPeeringAttachments`

---

### transit_gateway_policy_tabl_transit_gateway_policy_table

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayPolicyTables`

---

### transit_gateway_policy_table_entry_target_route_table

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetTransitGatewayPolicyTableEntries`

---

### transit_gateway_prefix_list_referenc_prefix_list_owner

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ❌ Cannot be produced from root operations

#### ⚠️  Requires DEPENDENT operations:

- `GetTransitGatewayPrefixListReferences`

---

### transit_gateway_route_table_announcement_core_network

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayRouteTableAnnouncements`

---

### transit_gateway_route_table_announcement_peer_core_network

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayRouteTableAnnouncements`

---

### transit_gateway_route_table_announcement_peer_transit_gateway

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayRouteTableAnnouncements`

---

### transit_gateway_route_table_announcement_peering_attachment

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayRouteTableAnnouncements`

---

### transit_gateway_route_table_announcement_transit_gateway_route_table

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeTransitGatewayRouteTableAnnouncements`
- `DescribeTransitGatewayRouteTables`

---

### verified_access_endpoint_verified_access_endpoint

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVerifiedAccessEndpoints`

---

### verified_access_endpoint_verified_access_group

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVerifiedAccessEndpoints`
- `DescribeVerifiedAccessGroups`

---

### verified_access_endpoint_verified_access_instance

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVerifiedAccessEndpoints`
- `DescribeVerifiedAccessGroups`
- `DescribeVerifiedAccessInstanceLoggingConfigurations`
- `DescribeVerifiedAccessInstances`

---

### verified_access_trust_provider_policy_reference

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVerifiedAccessTrustProviders`

---

### verified_access_trust_provider_verified_access_trust_provider

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVerifiedAccessTrustProviders`

---

### volum_source_volume

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVolumes`
- `ListVolumesInRecycleBin`

---

### vpc_block_public_access_exclusion_exclusion

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcBlockPublicAccessExclusions`

---

### vpc_block_public_access_option_aws_account

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcBlockPublicAccessOptions`

---

### vpc_encryption_control

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEncryptionControls`

---

### vpc_encryption_control_vpc_encryption_control

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEncryptionControls`

---

### vpc_endpoint_association

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpointAssociations`
- `GetAwsNetworkPerformanceData`

---

### vpc_endpoint_association_vpc_endpoint

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpointAssociations`
- `DescribeVpcEndpointConnectionNotifications`
- `DescribeVpcEndpointConnections`
- `DescribeVpcEndpoints`

---

### vpc_endpoint_connection_vpc_endpoint_connection

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcEndpointConnections`

---

### vpc_peering_connection_vpc_peering_connection

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpcPeeringConnections`

---

### vpn_concentrator

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpnConcentrators`

---

### vpn_concentrator_vpn_concentrator

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpnConcentrators`
- `DescribeVpnConnections`

---

### vpn_connection_device_typ_vpn_connection_device_type

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `GetVpnConnectionDeviceTypes`

---

### vpn_connection_vpn_connection

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpnConnections`

---

### vpn_connection_vpn_gateway

- **Status:** ❌ Not in inventory 📊 Use for enrichment
- **Classification:** SUB_RESOURCE
- **Has ARN:** No

#### ✅ Can be produced from ROOT operations:

- `DescribeVpnConnections`
- `DescribeVpnGateways`

---
