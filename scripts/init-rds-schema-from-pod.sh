#!/bin/bash
# Initialize RDS schema from within an EKS pod
# This avoids security group issues

set -e

NAMESPACE="threat-engine-engines"
SCHEMA_FILE="onboarding/database/schema.sql"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     RDS Schema Initialization from EKS Pod                      ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Check if we're in a pod or need to use kubectl
if [ -f "/var/run/secrets/kubernetes.io/serviceaccount/namespace" ]; then
    # Running inside pod
    echo "✅ Running inside Kubernetes pod"
    SCHEMA_PATH="/app/$SCHEMA_FILE"
else
    # Running locally, need to use kubectl
    echo "📋 Running from local machine, will use kubectl exec"
    
    # Find onboarding pod
    POD=$(kubectl get pod -l app=onboarding-api -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [ -z "$POD" ]; then
        echo "❌ No onboarding-api pod found. Deploy onboarding-api first."
        exit 1
    fi
    
    echo "✅ Found pod: $POD"
    
    # Copy schema file to pod
    echo "📝 Copying schema file to pod..."
    kubectl cp "$(pwd)/$SCHEMA_FILE" "$NAMESPACE/$POD:/tmp/schema.sql" || {
        echo "⚠️  Failed to copy schema. Trying alternative method..."
        # Create a temporary pod with postgres client
        kubectl run postgres-init-$(date +%s) \
          --image=postgres:14-alpine \
          --rm -it --restart=Never \
          --namespace="$NAMESPACE" \
          --env="PGPASSWORD=v-nKrqSta17I8UA1IPzIgoiJHPIE-zPm20V7D857yVU" \
          -- psql -h postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
          -U threatengine -d vulnerability_db \
          -f - < "$(pwd)/$SCHEMA_FILE"
        exit 0
    }
    
    # Execute schema from pod
    echo "📝 Executing schema..."
    kubectl exec "$POD" -n "$NAMESPACE" -- \
      python3 -c "
import psycopg2
import sys

try:
    conn = psycopg2.connect(
        host='postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com',
        port=5432,
        database='vulnerability_db',
        user='threatengine',
        password='v-nKrqSta17I8UA1IPzIgoiJHPIE-zPm20V7D857yVU'
    )
    cur = conn.cursor()
    
    # Read and execute schema
    with open('/tmp/schema.sql', 'r') as f:
        schema = f.read()
        cur.execute(schema)
    
    conn.commit()
    cur.close()
    conn.close()
    print('✅ Schema created successfully!')
except Exception as e:
    print(f'❌ Error: {e}')
    sys.exit(1)
" || {
        echo "⚠️  Python method failed, trying psql from pod..."
        kubectl exec "$POD" -n "$NAMESPACE" -- \
          sh -c "PGPASSWORD='v-nKrqSta17I8UA1IPzIgoiJHPIE-zPm20V7D857yVU' psql -h postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com -U threatengine -d vulnerability_db -f /tmp/schema.sql" || {
            echo "❌ Schema execution failed"
            exit 1
        }
    }
    
    echo "✅ Schema initialized from pod"
    exit 0
fi

# If running inside pod, execute directly
echo "📝 Executing schema..."
psql -h "$RDS_HOST" -U "$RDS_USER" -d "$RDS_DB" -f "$SCHEMA_PATH"

echo "✅ Schema initialized successfully!"

