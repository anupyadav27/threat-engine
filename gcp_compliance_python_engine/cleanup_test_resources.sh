#!/bin/bash

# GCP Test Resources Cleanup Script
# Project: test-2277
# Purpose: Remove test resources created for compliance testing

set -e

PROJECT="test-2277"
ZONE="us-central1-a"

echo "=========================================="
echo "GCP Test Resources Cleanup"
echo "Project: $PROJECT"
echo "=========================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}📋 Resources to be deleted:${NC}"
echo ""

# List compute instances
echo "1. Compute Instances:"
gcloud compute instances list --project=$PROJECT --filter="name~compliance-test" --format="table(name,zone,status)" 2>/dev/null || echo "  None found"
echo ""

# List firewall rules
echo "2. Firewall Rules:"
gcloud compute firewall-rules list --project=$PROJECT --filter="name~compliance-test" --format="table(name)" 2>/dev/null || echo "  None found"
echo ""

# List buckets
echo "3. Storage Buckets:"
gsutil ls -p $PROJECT 2>/dev/null | grep "compliance-test" || echo "  None found"
echo ""

echo "=========================================="
read -p "⚠️  Do you want to DELETE these resources? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo -e "${RED}❌ Cleanup cancelled${NC}"
    exit 0
fi

echo ""
echo -e "${GREEN}🗑️  Starting cleanup...${NC}"
echo ""

# Delete compute instances
echo "Deleting compute instances..."
INSTANCES=$(gcloud compute instances list --project=$PROJECT --filter="name~compliance-test" --format="value(name,zone)" 2>/dev/null)
if [ -n "$INSTANCES" ]; then
    while IFS=$'\t' read -r name zone; do
        echo "  Deleting instance: $name in $zone"
        gcloud compute instances delete "$name" --zone="$zone" --project=$PROJECT --quiet 2>&1 | grep -v "^Deleted" || true
    done <<< "$INSTANCES"
    echo -e "${GREEN}  ✅ Instances deleted${NC}"
else
    echo "  No instances to delete"
fi
echo ""

# Delete firewall rules
echo "Deleting firewall rules..."
FIREWALLS=$(gcloud compute firewall-rules list --project=$PROJECT --filter="name~compliance-test" --format="value(name)" 2>/dev/null)
if [ -n "$FIREWALLS" ]; then
    while read -r name; do
        echo "  Deleting firewall rule: $name"
        gcloud compute firewall-rules delete "$name" --project=$PROJECT --quiet 2>&1 | grep -v "^Deleted" || true
    done <<< "$FIREWALLS"
    echo -e "${GREEN}  ✅ Firewall rules deleted${NC}"
else
    echo "  No firewall rules to delete"
fi
echo ""

# Delete storage buckets
echo "Deleting storage buckets..."
BUCKETS=$(gsutil ls -p $PROJECT 2>/dev/null | grep "compliance-test" || true)
if [ -n "$BUCKETS" ]; then
    while read -r bucket; do
        echo "  Deleting bucket: $bucket"
        gsutil -m rm -r "$bucket" 2>&1 | grep -v "^Removing" || true
    done <<< "$BUCKETS"
    echo -e "${GREEN}  ✅ Buckets deleted${NC}"
else
    echo "  No buckets to delete"
fi
echo ""

echo "=========================================="
echo -e "${GREEN}✅ Cleanup Complete!${NC}"
echo "=========================================="
echo ""
echo "Remaining resources:"
echo ""
echo "Compute Instances:"
gcloud compute instances list --project=$PROJECT --format="table(name,zone,status)" 2>/dev/null | head -5
echo ""
echo "Storage Buckets:"
gsutil ls -p $PROJECT 2>/dev/null | wc -l | xargs -I {} echo "  {} buckets remaining"
