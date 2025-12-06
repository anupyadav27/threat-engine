#!/bin/bash
# ============================================================================
# GCP Compliance Engine - Systematic Service Validator
# ============================================================================
#
# This script validates ALL services one by one, running the engine for each
# and capturing results. Use this to systematically validate the entire engine.
#
# Usage: ./validate_all_services.sh [service_name]
#   - No args: Validate all services
#   - With arg: Validate specific service only
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Setup
ENGINE_DIR="/Users/apple/Desktop/threat-engine/gcp_compliance_python_engine"
OUTPUT_DIR="$ENGINE_DIR/output/validation_$(date +%Y%m%d_%H%M%S)"
RESULTS_FILE="$OUTPUT_DIR/validation_results.txt"

mkdir -p "$OUTPUT_DIR"

cd "$ENGINE_DIR"

# Activate venv
if [ ! -d "venv" ]; then
    echo -e "${RED}❌ Virtual environment not found${NC}"
    exit 1
fi

source venv/bin/activate
export PYTHONPATH="$(pwd)/..:$PYTHONPATH"

# Get list of services
get_services() {
    if [ -n "$1" ]; then
        # Single service mode
        echo "$1"
    else
        # All services
        find services -maxdepth 1 -type d -not -name "services" -exec basename {} \; | sort
    fi
}

# Validate a single service
validate_service() {
    local service=$1
    local service_file="services/$service/${service}_rules.yaml"
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}🔍 Validating: $service${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Check if rules file exists
    if [ ! -f "$service_file" ]; then
        echo -e "${RED}❌ Rules file not found: $service_file${NC}"
        echo "❌ $service - Rules file not found" >> "$RESULTS_FILE"
        return 1
    fi
    
    # Count discoveries and checks
    local discoveries=$(grep -c "discovery_id:" "$service_file" 2>/dev/null || echo "0")
    local checks=$(grep -c "check_id:" "$service_file" 2>/dev/null || echo "0")
    
    echo -e "📊 Discoveries: $discoveries"
    echo -e "📊 Checks: $checks"
    
    # Run engine for this service only
    local output_file="$OUTPUT_DIR/${service}_output.json"
    local error_file="$OUTPUT_DIR/${service}_errors.txt"
    
    echo -e "${YELLOW}⚙️  Running engine...${NC}"
    
    export GCP_ENGINE_FILTER_SERVICES="$service"
    
    if python engine/gcp_engine.py > "$output_file" 2> "$error_file"; then
        echo -e "${GREEN}✅ Engine completed${NC}"
        
        # Analyze output
        if [ -s "$output_file" ]; then
            # Check if valid JSON
            if python -m json.tool "$output_file" > /dev/null 2>&1; then
                # Count inventories and checks
                local inv_count=$(python -c "import json; data=json.load(open('$output_file')); print(len(data.get('inventories', [])))" 2>/dev/null || echo "0")
                local check_count=$(python -c "import json; data=json.load(open('$output_file')); print(len(data.get('main_checks', [])))" 2>/dev/null || echo "0")
                local skipped_count=$(python -c "import json; data=json.load(open('$output_file')); print(len(data.get('skipped_checks', [])))" 2>/dev/null || echo "0")
                
                echo -e "  📦 Inventories: $inv_count"
                echo -e "  ✓ Checks executed: $check_count"
                echo -e "  ⏭️  Checks skipped: $skipped_count"
                
                if [ "$inv_count" -gt 0 ] && [ "$check_count" -gt 0 ]; then
                    echo -e "${GREEN}✅ $service - VALIDATED (inv:$inv_count, checks:$check_count, skipped:$skipped_count)${NC}"
                    echo "✅ $service - VALIDATED (inv:$inv_count, checks:$check_count, skipped:$skipped_count)" >> "$RESULTS_FILE"
                else
                    echo -e "${YELLOW}⚠️  $service - NEEDS REVIEW (inv:$inv_count, checks:$check_count)${NC}"
                    echo "⚠️  $service - NEEDS REVIEW (inv:$inv_count, checks:$check_count)" >> "$RESULTS_FILE"
                fi
            else
                echo -e "${RED}❌ $service - INVALID JSON OUTPUT${NC}"
                echo "❌ $service - INVALID JSON OUTPUT" >> "$RESULTS_FILE"
            fi
        else
            echo -e "${RED}❌ $service - EMPTY OUTPUT${NC}"
            echo "❌ $service - EMPTY OUTPUT" >> "$RESULTS_FILE"
        fi
    else
        echo -e "${RED}❌ Engine failed${NC}"
        if [ -s "$error_file" ]; then
            echo -e "${RED}Errors:${NC}"
            head -20 "$error_file"
        fi
        echo "❌ $service - ENGINE FAILED" >> "$RESULTS_FILE"
    fi
    
    echo ""
}

# Main execution
echo -e "${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  GCP Compliance Engine - Service Validator   ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo "Output directory: $OUTPUT_DIR"
echo ""

# Get services to validate
SERVICES=$(get_services "$1")
SERVICE_COUNT=$(echo "$SERVICES" | wc -l | tr -d ' ')

echo "Services to validate: $SERVICE_COUNT"
echo ""

# Initialize results file
echo "GCP Compliance Engine - Validation Results" > "$RESULTS_FILE"
echo "Date: $(date)" >> "$RESULTS_FILE"
echo "======================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Validate each service
for service in $SERVICES; do
    validate_service "$service"
done

# Summary
echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}📊 VALIDATION SUMMARY${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Count results
VALIDATED=$(grep -c "✅.*VALIDATED" "$RESULTS_FILE" || echo "0")
NEEDS_REVIEW=$(grep -c "⚠️.*NEEDS REVIEW" "$RESULTS_FILE" || echo "0")
FAILED=$(grep -c "❌" "$RESULTS_FILE" || echo "0")

echo -e "${GREEN}✅ Validated: $VALIDATED${NC}"
echo -e "${YELLOW}⚠️  Needs Review: $NEEDS_REVIEW${NC}"
echo -e "${RED}❌ Failed: $FAILED${NC}"
echo ""
echo "Total Services: $SERVICE_COUNT"
echo ""

# Calculate percentage
if [ "$SERVICE_COUNT" -gt 0 ]; then
    PERCENT=$((VALIDATED * 100 / SERVICE_COUNT))
    echo "Success Rate: $PERCENT%"
fi

echo ""
echo "Full results: $RESULTS_FILE"
echo "Output files: $OUTPUT_DIR"
echo ""

if [ "$VALIDATED" -eq "$SERVICE_COUNT" ]; then
    echo -e "${GREEN}🎉 ALL SERVICES VALIDATED!${NC}"
else
    echo -e "${YELLOW}⚠️  Some services need attention. Check results file for details.${NC}"
fi

echo ""

