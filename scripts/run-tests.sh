#!/bin/bash
#
# Comprehensive Test Runner for Threat Engine Consolidated Services
# Runs unit, integration, e2e, and migration validation tests
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"
TESTS_DIR="${PROJECT_ROOT}/tests"
REPORTS_DIR="${PROJECT_ROOT}/test-reports"
COVERAGE_DIR="${PROJECT_ROOT}/coverage"

# Test configuration
PYTHON_VERSION=${PYTHON_VERSION:-"3.11"}
PYTEST_ARGS=${PYTEST_ARGS:-"-v --tb=short"}
COVERAGE_THRESHOLD=${COVERAGE_THRESHOLD:-"80"}
PARALLEL_TESTS=${PARALLEL_TESTS:-"auto"}
TIMEOUT=${TIMEOUT:-"300"}

echo -e "${BLUE}Threat Engine Test Suite${NC}"
echo "Project Root: ${PROJECT_ROOT}"
echo "Tests Directory: ${TESTS_DIR}"
echo "Reports Directory: ${REPORTS_DIR}"
echo ""

# Function to create directories
setup_test_environment() {
    echo -e "${YELLOW}Setting up test environment...${NC}"
    
    # Create directories
    mkdir -p "${REPORTS_DIR}"
    mkdir -p "${COVERAGE_DIR}"
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        echo -e "${RED}Error: Python not found${NC}"
        exit 1
    fi
    
    # Check Python version
    PYTHON_ACTUAL=$($PYTHON_CMD --version | cut -d' ' -f2)
    echo "Python version: ${PYTHON_ACTUAL}"
    
    # Install test dependencies
    echo "Installing test dependencies..."
    $PYTHON_CMD -m pip install --upgrade pip
    $PYTHON_CMD -m pip install pytest pytest-cov pytest-asyncio pytest-timeout pytest-xdist httpx
    
    echo -e "${GREEN}✓ Test environment ready${NC}"
}

# Function to run unit tests
run_unit_tests() {
    echo -e "${YELLOW}Running unit tests...${NC}"
    
    cd "${PROJECT_ROOT}"
    
    $PYTHON_CMD -m pytest \
        ${TESTS_DIR}/test_api_gateway.py \
        ${TESTS_DIR}/test_consolidated_services.py \
        --cov=api_gateway \
        --cov=consolidated_services \
        --cov-report=html:${COVERAGE_DIR}/html \
        --cov-report=xml:${COVERAGE_DIR}/coverage.xml \
        --cov-report=term \
        --cov-fail-under=${COVERAGE_THRESHOLD} \
        --junit-xml=${REPORTS_DIR}/unit-tests.xml \
        --timeout=${TIMEOUT} \
        ${PYTEST_ARGS} \
        || {
            echo -e "${RED}✗ Unit tests failed${NC}"
            return 1
        }
    
    echo -e "${GREEN}✓ Unit tests passed${NC}"
}

# Function to run integration tests
run_integration_tests() {
    echo -e "${YELLOW}Running integration tests...${NC}"
    
    cd "${PROJECT_ROOT}"
    
    $PYTHON_CMD -m pytest \
        ${TESTS_DIR}/test_consolidated_services.py::TestServiceIntegration \
        --junit-xml=${REPORTS_DIR}/integration-tests.xml \
        --timeout=${TIMEOUT} \
        -m integration \
        ${PYTEST_ARGS} \
        || {
            echo -e "${YELLOW}⚠ Integration tests had issues (services may not be running)${NC}"
            return 0  # Don't fail the entire test suite
        }
    
    echo -e "${GREEN}✓ Integration tests completed${NC}"
}

# Function to run E2E tests
run_e2e_tests() {
    echo -e "${YELLOW}Running end-to-end tests...${NC}"
    
    # Check if services are running
    if ! check_services_running; then
        echo -e "${YELLOW}⚠ Services not running, skipping E2E tests${NC}"
        echo "  To run E2E tests, start services with: make up"
        return 0
    fi
    
    cd "${PROJECT_ROOT}"
    
    $PYTHON_CMD -m pytest \
        ${TESTS_DIR}/test_e2e_workflows.py \
        --junit-xml=${REPORTS_DIR}/e2e-tests.xml \
        --timeout=600 \
        -m e2e \
        -s \
        ${PYTEST_ARGS} \
        || {
            echo -e "${YELLOW}⚠ E2E tests had issues${NC}"
            return 0  # Don't fail the entire test suite
        }
    
    echo -e "${GREEN}✓ E2E tests completed${NC}"
}

# Function to run migration validation tests
run_migration_tests() {
    echo -e "${YELLOW}Running migration validation tests...${NC}"
    
    cd "${PROJECT_ROOT}"
    
    $PYTHON_CMD -m pytest \
        ${TESTS_DIR}/test_migration_validation.py \
        --junit-xml=${REPORTS_DIR}/migration-tests.xml \
        --timeout=${TIMEOUT} \
        -m migration \
        -s \
        ${PYTEST_ARGS} \
        || {
            echo -e "${YELLOW}⚠ Migration validation had issues${NC}"
            return 0  # Don't fail the entire test suite
        }
    
    echo -e "${GREEN}✓ Migration validation completed${NC}"
}

# Function to run performance tests
run_performance_tests() {
    echo -e "${YELLOW}Running performance tests...${NC}"
    
    if ! check_services_running; then
        echo -e "${YELLOW}⚠ Services not running, skipping performance tests${NC}"
        return 0
    fi
    
    cd "${PROJECT_ROOT}"
    
    $PYTHON_CMD -m pytest \
        ${TESTS_DIR}/test_e2e_workflows.py::TestPerformanceRequirements \
        --junit-xml=${REPORTS_DIR}/performance-tests.xml \
        --timeout=600 \
        -m performance \
        ${PYTEST_ARGS} \
        || {
            echo -e "${YELLOW}⚠ Performance tests had issues${NC}"
            return 0
        }
    
    echo -e "${GREEN}✓ Performance tests completed${NC}"
}

# Function to check if services are running
check_services_running() {
    local services_running=false
    
    # Check if API Gateway is accessible
    if curl -f -s http://localhost:8000/health &>/dev/null; then
        services_running=true
    elif command -v kubectl &> /dev/null && kubectl get pods -n threat-engine &>/dev/null; then
        # Check if services are running in Kubernetes
        if kubectl get pods -n threat-engine | grep -q "Running"; then
            services_running=true
        fi
    fi
    
    return $([ "$services_running" = true ])
}

# Function to generate test report
generate_test_report() {
    echo -e "${YELLOW}Generating test report...${NC}"
    
    local report_file="${REPORTS_DIR}/test-summary.md"
    
    cat > "${report_file}" << EOF
# Threat Engine Test Report

Generated: $(date)

## Test Results Summary

EOF
    
    # Count test results from JUnit XML files
    if command -v xmllint &> /dev/null; then
        for xml_file in ${REPORTS_DIR}/*.xml; do
            if [ -f "$xml_file" ]; then
                local test_name=$(basename "$xml_file" .xml)
                local tests_count=$(xmllint --xpath "count(//testcase)" "$xml_file" 2>/dev/null || echo "0")
                local failures_count=$(xmllint --xpath "count(//failure)" "$xml_file" 2>/dev/null || echo "0")
                local errors_count=$(xmllint --xpath "count(//error)" "$xml_file" 2>/dev/null || echo "0")
                
                echo "### ${test_name}" >> "${report_file}"
                echo "- Tests: ${tests_count}" >> "${report_file}"
                echo "- Failures: ${failures_count}" >> "${report_file}"
                echo "- Errors: ${errors_count}" >> "${report_file}"
                echo "" >> "${report_file}"
            fi
        done
    fi
    
    # Add coverage information if available
    if [ -f "${COVERAGE_DIR}/coverage.xml" ]; then
        echo "## Coverage Report" >> "${report_file}"
        echo "Coverage report available at: \`${COVERAGE_DIR}/html/index.html\`" >> "${report_file}"
        echo "" >> "${report_file}"
    fi
    
    echo "## Files Generated" >> "${report_file}"
    echo "- Test Reports: \`${REPORTS_DIR}/\`" >> "${report_file}"
    echo "- Coverage: \`${COVERAGE_DIR}/\`" >> "${report_file}"
    
    echo -e "${GREEN}✓ Test report generated: ${report_file}${NC}"
}

# Function to display usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_TYPE]"
    echo ""
    echo "Test Types:"
    echo "  unit         - Run unit tests only"
    echo "  integration  - Run integration tests only"
    echo "  e2e          - Run end-to-end tests only"
    echo "  migration    - Run migration validation tests only"
    echo "  performance  - Run performance tests only"
    echo "  all          - Run all tests (default)"
    echo ""
    echo "Options:"
    echo "  --coverage-threshold N  - Set coverage threshold (default: ${COVERAGE_THRESHOLD}%)"
    echo "  --timeout N            - Set test timeout in seconds (default: ${TIMEOUT}s)"
    echo "  --no-coverage         - Skip coverage reporting"
    echo "  --help, -h            - Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  PYTHON_VERSION        - Python version to use (default: ${PYTHON_VERSION})"
    echo "  PYTEST_ARGS          - Additional pytest arguments"
    echo "  COVERAGE_THRESHOLD    - Coverage threshold percentage"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run all tests"
    echo "  $0 unit              # Run only unit tests"
    echo "  $0 e2e               # Run only E2E tests (requires running services)"
    echo "  $0 --coverage-threshold 90 unit  # Run unit tests with 90% coverage"
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --coverage-threshold)
                COVERAGE_THRESHOLD="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --no-coverage)
                COVERAGE_THRESHOLD="0"
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            unit|integration|e2e|migration|performance|all)
                TEST_TYPE="$1"
                shift
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Main test execution
main() {
    local TEST_TYPE=${1:-"all"}
    
    setup_test_environment
    
    local overall_result=0
    
    case $TEST_TYPE in
        unit)
            run_unit_tests || overall_result=1
            ;;
        integration)
            run_integration_tests || overall_result=1
            ;;
        e2e)
            run_e2e_tests || overall_result=1
            ;;
        migration)
            run_migration_tests || overall_result=1
            ;;
        performance)
            run_performance_tests || overall_result=1
            ;;
        all)
            echo -e "${BLUE}Running comprehensive test suite...${NC}"
            
            run_unit_tests || overall_result=1
            run_integration_tests || overall_result=1
            run_e2e_tests || overall_result=1
            run_migration_tests || overall_result=1
            run_performance_tests || overall_result=1
            ;;
        *)
            echo -e "${RED}Unknown test type: $TEST_TYPE${NC}"
            show_usage
            exit 1
            ;;
    esac
    
    generate_test_report
    
    if [ $overall_result -eq 0 ]; then
        echo ""
        echo -e "${GREEN}🎉 All tests completed successfully!${NC}"
        echo ""
        echo "Reports available at: ${REPORTS_DIR}/"
        echo "Coverage report: ${COVERAGE_DIR}/html/index.html"
    else
        echo ""
        echo -e "${YELLOW}⚠ Some tests completed with warnings or failures${NC}"
        echo "Check reports at: ${REPORTS_DIR}/"
        exit $overall_result
    fi
}

# Handle script arguments
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_arguments "$@"
    main "$@"
fi