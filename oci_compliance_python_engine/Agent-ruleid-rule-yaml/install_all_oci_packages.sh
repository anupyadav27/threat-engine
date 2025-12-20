#!/bin/bash
# Install all OCI SDK packages

echo "Installing OCI SDK packages..."
echo "================================"

# Core OCI package (includes many services)
pip install oci

# Individual service packages (if needed)
pip install oci-core oci-identity oci-database oci-object-storage \
            oci-compute oci-container-engine oci-data-science \
            oci-monitoring oci-logging oci-dns oci-file-storage \
            oci-streaming oci-data-catalog oci-data-integration \
            oci-cloud-guard oci-apigateway oci-events oci-audit \
            oci-waf oci-edge-services oci-mysql oci-data-flow \
            oci-nosql oci-devops oci-artifacts oci-certificates \
            oci-resource-manager oci-bds oci-data-safe oci-ons \
            oci-network-firewall oci-queue oci-redis \
            oci-container-instances oci-ai-anomaly-detection \
            oci-ai-language oci-vault oci-analytics

echo ""
echo "✅ OCI SDK packages installed"
echo ""
echo "To verify installation, run:"
echo "  python3 -c 'import oci; print(\"OCI SDK version:\", oci.__version__)'"

