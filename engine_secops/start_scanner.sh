#!/bin/bash

# Quick Start Script for SecOps Scanner
# Deploys Scanner API in Docker with input/output folders

set -e

echo "🚀 Starting SecOps Vulnerability Scanner..."
echo "================================================"

# Navigate to scanner directory
cd "$(dirname "$0")/scanner_engine"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Create input/output folders if they don't exist
mkdir -p scan_input scan_output

echo "📁 Input folder:  $(pwd)/scan_input"
echo "📁 Output folder: $(pwd)/scan_output"

# Stop existing container if running
if docker ps -a | grep -q secops-scanner; then
    echo "🛑 Stopping existing scanner container..."
    docker-compose down
fi

# Build and start
echo "🏗️  Building and starting scanner..."
docker-compose up -d --build

# Wait for healthcheck
echo "⏳ Waiting for scanner to be ready..."
sleep 5

# Check health
MAX_RETRIES=10
RETRY=0
while [ $RETRY -lt $MAX_RETRIES ]; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo "✅ Scanner is healthy!"
        break
    fi
    RETRY=$((RETRY+1))
    echo "   Retry $RETRY/$MAX_RETRIES..."
    sleep 2
done

if [ $RETRY -eq $MAX_RETRIES ]; then
    echo "❌ Scanner failed to start. Check logs:"
    echo "   docker logs secops-scanner"
    exit 1
fi

# Display info
echo ""
echo "================================================"
echo "✅ Scanner API is running!"
echo "================================================"
echo ""
echo "📍 API URL:       http://localhost:8000"
echo "📖 Docs:          http://localhost:8000/docs"
echo "🏥 Health:        http://localhost:8000/health"
echo ""
echo "📂 Folders:"
echo "   Input:  $(pwd)/scan_input   (Clone repos here)"
echo "   Output: $(pwd)/scan_output  (Results saved here)"
echo ""
echo "🔧 Management:"
echo "   View logs:    docker logs -f secops-scanner"
echo "   Stop:         docker-compose down"
echo "   Restart:      docker-compose restart"
echo ""
echo "🧪 Test the scanner:"
echo "   curl http://localhost:8000/health | jq '.'"
echo ""

