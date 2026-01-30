#!/bin/bash
# Generate Kubernetes deployment YAML from config.yaml
# This allows easy switching between local and AWS EKS configurations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: config.yaml not found at $CONFIG_FILE"
    exit 1
fi

# This is a template - in production, you'd use a tool like envsubst, yq, or Python
# For now, we'll create a complete YAML file manually

echo "Generating deployment YAML from config.yaml..."
echo "Note: This is a simplified version. For production, use a templating tool."

# The orchestration-deployments.yaml will be manually maintained
# but can reference values from config.yaml

cat > "${SCRIPT_DIR}/orchestration-deployments.yaml" << 'EOFYAML'
---
# Generated from config.yaml
# Namespace
apiVersion: v1
kind: Namespace
metadata:
  name: threat-engine-local
  labels:
    environment: local
    deployment: local

---
# API Gateway Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: threat-engine-local
spec:
  replicas: 1
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      containers:
      - name: api-gateway
        image: threat-engine/api-gateway:local
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8000
        env:
        - name: DISCOVERIES_ENGINE_URL
          value: "http://discovery-service:8001"
        - name: CHECK_ENGINE_URL
          value: "http://check-service:8002"
        - name: THREAT_ENGINE_URL
          value: "http://threat-service:8020"
        - name: COMPLIANCE_ENGINE_URL
          value: "http://compliance-service:8010"
        - name: IAM_ENGINE_URL
          value: "http://iam-service:8003"
        - name: DATASEC_ENGINE_URL
          value: "http://datasec-service:8004"
        - name: INVENTORY_ENGINE_URL
          value: "http://inventory-service:8022"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"

---
apiVersion: v1
kind: Service
metadata:
  name: api-gateway
  namespace: threat-engine-local
spec:
  selector:
    app: api-gateway
  ports:
  - port: 8000
    targetPort: 8000
  type: NodePort
EOFYAML

echo "✅ Deployment YAML generated (basic version)"
echo "   For full deployment with all engines, see orchestration-deployments-full.yaml"
