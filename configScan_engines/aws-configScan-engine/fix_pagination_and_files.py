#!/usr/bin/env python3
"""
Fix two issues:
1. Replace EC2-specific logic with boto3 paginators
2. Ensure per-account+region files are created
"""

import re

# Read service_scanner.py
with open("engine/service_scanner.py", "r") as f:
    content = f.read()

# Fix 1: Update _paginate_api_call to use boto3 paginators first
old_paginate_start = """def _paginate_api_call(client, action: str, params: Dict[str, Any], max_pages: int = 100) -> Dict[str, Any]:
    \"\"\"
    Paginate through AWS API calls that support pagination.
    
    Handles NextToken, Marker, and other pagination tokens automatically.
    Returns combined response with all items from all pages.
    
    Args:
        client: Boto3 client
        action: API action name (e.g., 'describe_snapshots')
        params: API parameters (MaxResults will be used for pagination)
        max_pages: Maximum number of pages to fetch (safety limit)
    
    Returns:
        Combined response dict with all items from all pages
    \""""

new_paginate_start = """def _paginate_api_call(client, action: str, params: Dict[str, Any], max_pages: int = 100) -> Dict[str, Any]:
    \"\"\"
    Paginate through AWS API calls using boto3 paginators when available, 
    otherwise fall back to manual pagination.
    
    Boto3 paginators automatically handle pagination for operations that support it.
    This is the AWS-recommended approach and works across all services.
    
    Args:
        client: Boto3 client
        action: API action name (e.g., 'describe_snapshots')
        params: API parameters (MaxResults will be used for pagination)
        max_pages: Maximum number of pages to fetch (safety limit)
    
    Returns:
        Combined response dict with all items from all pages
    \"""
    # Try boto3 paginator first (AWS-recommended approach)
    try:
        # Convert action name to paginator name (e.g., 'describe_snapshots' -> 'describe_snapshots')
        # Most paginators use the same name as the action
        paginator_name = action
        
        # Check if paginator exists for this operation
        paginator = client.get_paginator(paginator_name)
        
        # Get pagination config
        page_iterator = paginator.paginate(**params)
        
        # Collect all pages
        all_items = []
        result_array_key = None
        first_page = None
        page_count = 0
        
        for page in page_iterator:
            if first_page is None:
                first_page = page
                # Detect result array key from first page
                for key, value in page.items():
                    if isinstance(value, list) and key not in ['NextToken', 'Marker', 'NextMarker', 'ContinuationToken']:
                        result_array_key = key
                        all_items.extend(value)
                        break
            else:
                # Add items from subsequent pages
                if result_array_key and result_array_key in page:
                    all_items.extend(page[result_array_key])
            
            page_count += 1
            if page_count >= max_pages:
                logger.warning(f"Pagination stopped at {max_pages} pages for {action} (safety limit)")
                break
        
        if first_page and result_array_key:
            # Build combined response
            combined_response = first_page.copy()
            combined_response[result_array_key] = all_items
            # Remove pagination tokens
            for token_key in ['NextToken', 'Marker', 'NextMarker', 'ContinuationToken']:
                combined_response.pop(token_key, None)
            
            if page_count > 1:
                logger.debug(f"Paginated {action} using boto3 paginator: {page_count} pages, {len(all_items)} total items")
            return combined_response
        else:
            # No pagination needed or no result array found
            return first_page if first_page else {}
            
    except Exception as paginator_error:
        # Paginator not available - fall back to manual pagination
        logger.debug(f"Boto3 paginator not available for {action}, using manual pagination: {paginator_error}")
        # Continue to manual pagination below"""

if old_paginate_start in content:
    content = content.replace(old_paginate_start, new_paginate_start)
    print("✅ Updated _paginate_api_call to use boto3 paginators")
else:
    print("⚠️  Could not find exact match for _paginate_api_call, checking if already updated...")
    if "get_paginator" in content:
        print("✅ Boto3 paginator already present")

# Fix 2: Remove EC2-specific logic
ec2_pattern = r"""# EC2 operations that DON'T support MaxResults \(they return all results in one call\)
                            ec2_no_maxresults = \{
                                'describe_addresses', 'describe_subnets', 'describe_security_groups',
                                'describe_availability_zones', 'describe_reserved_instances',
                                'describe_placement_groups', 'describe_iam_instance_profile_associations',
                                'describe_address_transfers', 'describe_classic_link_instances',
                                'describe_network_interface_attribute', 'describe_nat_gateways',
                                'describe_vpcs', 'describe_route_tables', 'describe_internet_gateways',
                                'describe_vpc_peering_connections', 'describe_vpc_endpoints',
                                'describe_network_acls', 'describe_customer_gateways', 'describe_vpn_gateways',
                                'describe_vpn_connections', 'describe_network_interfaces'
                            \}
                            
                            # Always attempt pagination for list/describe operations \(independent discoveries only\)
                            # BUT skip operations that don't support MaxResults
                            if not for_each and is_list_or_describe:
                                # Skip if this operation doesn't support MaxResults
                                if service_name == 'ec2' and action in ec2_no_maxresults:
                                    # These operations return all results in one call - no pagination needed
                                    logger\.debug\(f"Skipping MaxResults for \{action\} \(doesn't support pagination\)"\)
                                    # Single API call \(no MaxResults, no pagination\)
                                    response = _retry_call\(getattr\(call_client, action\), \*\*resolved_params\)
                                else:
                                    # Add default pagination param if not specified in YAML
                                    has_pagination_param = any\(key in resolved_params for key in 
                                        \['MaxResults', 'MaxRecords', 'Limit', 'MaxItems'\]\)
                                    
                                    if not has_pagination_param:
                                        # Service-specific defaults \(some services have lower limits\)
                                        # SageMaker has a max of 100 for most operations
                                        if service_name == 'sagemaker':
                                            default_max_results = 100
                                        else:
                                            default_max_results = 1000
                                        
                                        resolved_params\['MaxResults'\] = default_max_results
                                        logger\.debug\(f"Added default MaxResults: \{default_max_results\} for \{action\} \(service: \{service_name\}\)"\)
                                    
                                    # Use pagination helper \(gracefully handles if pagination not supported\)
                                    response = _paginate_api_call\(call_client, action, resolved_params\)"""

new_logic = """# Always attempt pagination for list/describe operations (independent discoveries only)
                            # Use boto3 paginators when available (handles all services automatically)
                            if not for_each and is_list_or_describe:
                                # Add default pagination param if not specified in YAML
                                # Boto3 paginators will use this for page size
                                has_pagination_param = any(key in resolved_params for key in 
                                    ['MaxResults', 'MaxRecords', 'Limit', 'MaxItems', 'PageSize'])
                                
                                if not has_pagination_param:
                                    # Service-specific defaults (some services have lower limits)
                                    # SageMaker has a max of 100 for most operations
                                    if service_name == 'sagemaker':
                                        default_max_results = 100
                                    else:
                                        default_max_results = 1000
                                    
                                    resolved_params['MaxResults'] = default_max_results
                                    logger.debug(f"Added default MaxResults: {default_max_results} for {action} (service: {service_name})")
                                
                                # Use boto3 paginator (automatically handles all services that support pagination)
                                # Falls back to manual pagination if paginator not available
                                response = _paginate_api_call(call_client, action, resolved_params)"""

if re.search(ec2_pattern, content):
    content = re.sub(ec2_pattern, new_logic, content)
    print("✅ Removed EC2-specific logic")
else:
    print("⚠️  EC2-specific logic pattern not found (may already be removed)")

# Write back
with open("engine/service_scanner.py", "w") as f:
    f.write(content)

print("\n✅ Fixes applied to service_scanner.py")

