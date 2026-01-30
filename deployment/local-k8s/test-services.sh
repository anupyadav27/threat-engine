#!/bin/bash

# Test Threat Engine Services
# Tests health endpoints and basic functionality

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

NAMESPACE="threat-engine-local"
ONBOARDING_URL="http://localhost:30010"
CONFIGSCAN_URL="http://localhost:30002"

print_header() {
    echo -e "\n${BLUE}===================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

test_endpoint() {
    local url=$1
    local name=$2
    
    echo "Testing $name..."
    response=$(curl -s -w "\n%{http_code}" "$url" || echo -e "\n000")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [ "$http_code" = "200" ]; then
        print_success "$name: HTTP $http_code"
        echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
        return 0
    else
        print_error "$name: HTTP $http_code"
        echo "$body"
        return 1
    fi
}

test_onboarding() {
    print_header "Testing Onboarding Engine"
    
    # Test root endpoint
    test_endpoint "$ONBOARDING_URL/" "Onboarding Root"
    
    # Test health endpoint
    test_endpoint "$ONBOARDING_URL/api/v1/health" "Onboarding Health"
    
    # Test readiness
    test_endpoint "$ONBOARDING_URL/api/v1/health/ready" "Onboarding Readiness"
    
    # Test liveness
    test_endpoint "$ONBOARDING_URL/api/v1/health/live" "Onboarding Liveness"
}

test_configscan() {
    print_header "Testing ConfigScan AWS Engine"
    
    # Test health endpoint
    test_endpoint "$CONFIGSCAN_URL/api/v1/health" "ConfigScan AWS Health"
    
    # Test readiness
    test_endpoint "$CONFIGSCAN_URL/api/v1/health/ready" "ConfigScan AWS Readiness"
    
    # Test liveness
    test_endpoint "$CONFIGSCAN_URL/api/v1/health/live" "ConfigScan AWS Liveness"
    
    # Test services endpoint
    test_endpoint "$CONFIGSCAN_URL/api/v1/services" "ConfigScan AWS Services"
}

test_database_connectivity() {
    print_header "Testing Database Connectivity from Pods"
    
    # Test onboarding database
    ONBOARDING_POD=$(kubectl get pods -n "$NAMESPACE" -l app=onboarding-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ -n "$ONBOARDING_POD" ]; then
        echo "Testing database connection from onboarding pod..."
        kubectl exec -n "$NAMESPACE" "$ONBOARDING_POD" -- \
            python3 -c "
import os
import sys
try:
    from engine_onboarding.database.connection import check_connection
    if check_connection():
        print('✓ Database connection successful')
        sys.exit(0)
    else:
        print('✗ Database connection failed')
        sys.exit(1)
except Exception as e:
    print(f'✗ Database connection error: {e}')
    sys.exit(1)
" && print_success "Onboarding database connection OK" || print_error "Onboarding database connection failed"
    fi
    
    # Test configscan database
    CONFIGSCAN_POD=$(kubectl get pods -n "$NAMESPACE" -l app=configscan-aws-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ -n "$CONFIGSCAN_POD" ]; then
        echo "Testing database connection from configscan pod..."
        kubectl exec -n "$NAMESPACE" "$CONFIGSCAN_POD" -- \
            python3 -c "
import os
import sys
try:
    from engine.database_manager import DatabaseManager
    db = DatabaseManager()
    conn = db._get_connection()
    if conn:
        print('✓ Database connection successful')
        db.connection_pool.putconn(conn)
        sys.exit(0)
    else:
        print('✗ Database connection failed')
        sys.exit(1)
except Exception as e:
    print(f'✗ Database connection error: {e}')
    sys.exit(1)
" && print_success "ConfigScan database connection OK" || print_error "ConfigScan database connection failed"
    fi
}

main() {
    print_header "Threat Engine Service Tests"
    
    # Check if services are running
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        print_error "Namespace $NAMESPACE not found. Deploy services first."
        exit 1
    fi
    
    # Test endpoints
    test_onboarding
    test_configscan
    
    # Test database connectivity
    test_database_connectivity
    
    print_header "Test Summary"
    echo "All tests completed. Check output above for results."
}

main "$@"
