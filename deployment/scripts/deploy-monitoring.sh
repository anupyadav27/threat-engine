#!/bin/bash
#
# Deploy Monitoring Stack for Consolidated Services
# Deploys Prometheus, Grafana, Elasticsearch, and Kibana
#

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

NAMESPACE=${NAMESPACE:-"threat-engine"}
MONITORING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../monitoring" &> /dev/null && pwd)"

echo -e "${BLUE}Deploying Threat Engine Monitoring Stack${NC}"
echo "Namespace: ${NAMESPACE}"
echo "Monitoring Config: ${MONITORING_DIR}"
echo ""

# Function to check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    if ! command -v kubectl &> /dev/null; then
        echo "kubectl is required but not installed"
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        echo "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Prerequisites checked${NC}"
}

# Function to create monitoring namespace
create_namespace() {
    echo -e "${YELLOW}Creating namespace...${NC}"
    
    kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
    kubectl label namespace "${NAMESPACE}" monitoring=enabled --overwrite
    
    echo -e "${GREEN}✓ Namespace ready${NC}"
}

# Function to deploy Prometheus
deploy_prometheus() {
    echo -e "${YELLOW}Deploying Prometheus...${NC}"
    
    # Apply configs first
    kubectl apply -f "${MONITORING_DIR}/prometheus-config.yaml" -n "${NAMESPACE}"
    kubectl apply -f "${MONITORING_DIR}/alerting-rules.yaml" -n "${NAMESPACE}"
    
    # Deploy Prometheus and Grafana
    kubectl apply -f "${MONITORING_DIR}/prometheus-deployment.yaml" -n "${NAMESPACE}"
    
    # Wait for deployment
    kubectl wait --for=condition=available --timeout=300s deployment/prometheus -n "${NAMESPACE}"
    kubectl wait --for=condition=available --timeout=300s deployment/grafana -n "${NAMESPACE}"
    
    echo -e "${GREEN}✓ Prometheus and Grafana deployed${NC}"
}

# Function to deploy logging stack
deploy_logging() {
    echo -e "${YELLOW}Deploying logging stack...${NC}"
    
    kubectl apply -f "${MONITORING_DIR}/logging-stack.yaml" -n "${NAMESPACE}"
    
    # Wait for Elasticsearch to be ready
    kubectl wait --for=condition=available --timeout=600s deployment/elasticsearch -n "${NAMESPACE}"
    kubectl wait --for=condition=available --timeout=300s deployment/kibana -n "${NAMESPACE}"
    
    echo -e "${GREEN}✓ Logging stack deployed${NC}"
}

# Function to create Grafana secret
create_grafana_secret() {
    echo -e "${YELLOW}Creating Grafana credentials...${NC}"
    
    # Generate random password
    GRAFANA_PASSWORD=$(openssl rand -base64 12)
    
    kubectl create secret generic grafana-credentials \
        --from-literal=admin_password="${GRAFANA_PASSWORD}" \
        -n "${NAMESPACE}" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    echo -e "${GREEN}✓ Grafana credentials created${NC}"
    echo -e "${BLUE}Grafana admin password: ${GRAFANA_PASSWORD}${NC}"
}

# Function to configure service monitors
configure_service_monitors() {
    echo -e "${YELLOW}Configuring service monitors...${NC}"
    
    # Add Prometheus scraping annotations to service deployments
    kubectl patch deployment api-gateway -n "${NAMESPACE}" -p '{
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "prometheus.io/scrape": "true",
                        "prometheus.io/port": "8000",
                        "prometheus.io/path": "/metrics"
                    }
                }
            }
        }
    }' || echo "API Gateway not found, skipping..."
    
    # Patch other services
    for service in core-engine-service configscan-service platform-service data-secops-service; do
        kubectl patch deployment "${service}" -n "${NAMESPACE}" -p "{
            \"spec\": {
                \"template\": {
                    \"metadata\": {
                        \"annotations\": {
                            \"prometheus.io/scrape\": \"true\",
                            \"prometheus.io/port\": \"800${service: -1}\",
                            \"prometheus.io/path\": \"/metrics\"
                        }
                    }
                }
            }
        }" || echo "${service} not found, skipping..."
    done
    
    echo -e "${GREEN}✓ Service monitors configured${NC}"
}

# Function to show access information
show_access_info() {
    echo ""
    echo -e "${GREEN}🎉 Monitoring stack deployed successfully!${NC}"
    echo ""
    echo -e "${BLUE}Access Information:${NC}"
    
    # Get service IPs
    GRAFANA_IP=$(kubectl get service grafana -n "${NAMESPACE}" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
    KIBANA_IP=$(kubectl get service kibana -n "${NAMESPACE}" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
    
    if [ "$GRAFANA_IP" != "pending" ] && [ -n "$GRAFANA_IP" ]; then
        echo "Grafana: http://${GRAFANA_IP}:3000"
    else
        echo "Grafana: kubectl port-forward -n ${NAMESPACE} service/grafana 3000:3000"
    fi
    
    if [ "$KIBANA_IP" != "pending" ] && [ -n "$KIBANA_IP" ]; then
        echo "Kibana: http://${KIBANA_IP}:5601"
    else
        echo "Kibana: kubectl port-forward -n ${NAMESPACE} service/kibana 5601:5601"
    fi
    
    echo "Prometheus: kubectl port-forward -n ${NAMESPACE} service/prometheus 9090:9090"
    echo "Elasticsearch: kubectl port-forward -n ${NAMESPACE} service/elasticsearch 9200:9200"
    
    echo ""
    echo -e "${BLUE}Default Credentials:${NC}"
    echo "Grafana - admin / (password shown above)"
    
    echo ""
    echo -e "${BLUE}Useful Commands:${NC}"
    echo "• View Prometheus targets: kubectl port-forward -n ${NAMESPACE} service/prometheus 9090:9090"
    echo "• Import Grafana dashboard: Use the dashboard JSON from monitoring/grafana-dashboard.json"
    echo "• View logs in Kibana: Create index pattern 'threat-engine-*'"
    echo "• Check alert status: kubectl logs -f deployment/prometheus -n ${NAMESPACE}"
}

# Function to verify deployment
verify_deployment() {
    echo -e "${YELLOW}Verifying monitoring deployment...${NC}"
    
    # Check all deployments are ready
    local failed_deployments=()
    
    for deployment in prometheus grafana elasticsearch kibana; do
        if ! kubectl rollout status deployment/"$deployment" -n "${NAMESPACE}" --timeout=30s &> /dev/null; then
            failed_deployments+=("$deployment")
        fi
    done
    
    if [ ${#failed_deployments[@]} -eq 0 ]; then
        echo -e "${GREEN}✓ All monitoring services are ready${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ Some services may still be starting: ${failed_deployments[*]}${NC}"
        return 1
    fi
}

# Main deployment function
main() {
    check_prerequisites
    create_namespace
    create_grafana_secret
    deploy_prometheus
    deploy_logging
    configure_service_monitors
    
    if verify_deployment; then
        show_access_info
    else
        echo -e "${YELLOW}Monitoring stack deployed but some services may still be starting${NC}"
        echo "Run 'kubectl get pods -n ${NAMESPACE}' to check status"
        show_access_info
    fi
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "status")
        kubectl get all -n "${NAMESPACE}"
        ;;
    "clean")
        echo -e "${YELLOW}Removing monitoring stack...${NC}"
        kubectl delete -f "${MONITORING_DIR}/logging-stack.yaml" -n "${NAMESPACE}" || true
        kubectl delete -f "${MONITORING_DIR}/prometheus-deployment.yaml" -n "${NAMESPACE}" || true
        kubectl delete -f "${MONITORING_DIR}/alerting-rules.yaml" -n "${NAMESPACE}" || true
        kubectl delete -f "${MONITORING_DIR}/prometheus-config.yaml" -n "${NAMESPACE}" || true
        echo -e "${GREEN}✓ Monitoring stack removed${NC}"
        ;;
    "help")
        echo "Usage: $0 [deploy|status|clean|help]"
        echo ""
        echo "Commands:"
        echo "  deploy - Deploy monitoring stack"
        echo "  status - Show deployment status"
        echo "  clean  - Remove monitoring stack"
        echo "  help   - Show this help"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac