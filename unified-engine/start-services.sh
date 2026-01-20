#!/bin/bash

# Fallback startup script if supervisor is not available
# This runs all services in background

echo "Starting all engines in unified container..."

# Start AWS Engine on port 8000
echo "Starting AWS Compliance Engine on port 8000..."
cd /app
uvicorn aws_api_server:app --host 0.0.0.0 --port 8000 --timeout-keep-alive 75 &
AWS_PID=$!

# Start Compliance Engine on port 8001
echo "Starting Compliance Engine on port 8001..."
uvicorn compliance_engine.api_server:app --host 0.0.0.0 --port 8001 &
COMPLIANCE_PID=$!

# Start Rule Engine on port 8002
echo "Starting Rule Engine on port 8002..."
uvicorn rule_api_server:app --host 0.0.0.0 --port 8002 &
RULE_PID=$!

echo "All services started!"
echo "AWS Engine PID: $AWS_PID"
echo "Compliance Engine PID: $COMPLIANCE_PID"
echo "Rule Engine PID: $RULE_PID"

# Wait for all processes
wait

