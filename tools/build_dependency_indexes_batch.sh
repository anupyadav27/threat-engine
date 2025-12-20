#!/bin/bash
# Batch script to build dependency indexes with progress tracking and resume capability

ROOT_PATH="pythonsdk-database/aws"
PROVIDER="aws"
LIMIT=${1:-10}  # Default to 10 for testing, pass number as first arg
VALIDATE="--validate"

echo "Building dependency indexes for AWS services"
echo "Limit: $LIMIT services"
echo "Starting at $(date)"
echo ""

# Run with limit
python3 tools/build_all_dependency_indexes.py "$ROOT_PATH" \
    --provider "$PROVIDER" \
    --limit "$LIMIT" \
    $VALIDATE

echo ""
echo "Completed at $(date)"

