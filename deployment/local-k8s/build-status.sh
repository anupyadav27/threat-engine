#!/bin/bash
# Check build status and show progress

echo "=========================================="
echo "Docker Build Status Check"
echo "=========================================="
echo ""

echo "Built Images:"
docker images | grep threat-engine | awk '{printf "  %-30s %-15s %s\n", $1, $2, $7" "$8}'

echo ""
echo "Build Processes:"
ps aux | grep docker | grep build | grep -v grep | head -5 || echo "  No active builds"

echo ""
echo "To monitor build progress:"
echo "  docker ps -a | grep build"
echo ""
echo "To view build logs:"
echo "  tail -f deployment/local-k8s/build.log"
