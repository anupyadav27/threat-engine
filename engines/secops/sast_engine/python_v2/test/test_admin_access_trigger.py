# Test script to trigger 'administration_services_access_should_be_restricted_to_specific_ip_addresses'

# Noncompliant: Admin service accessible from any IP
admin_service = {
    'name': 'admin',
    'cidr_blocks': ['0.0.0.0/0']  # Unrestricted access
}

# Compliant: Admin service restricted to specific IPs
restricted_admin_service = {
    'name': 'admin',
    'cidr_blocks': ['192.168.1.1', '192.168.1.2']
}
