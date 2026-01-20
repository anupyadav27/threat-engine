#!/bin/bash
# Cleanup outdated files and update references

set -e

echo "=== Cleaning Up Outdated Files ==="
echo ""

# 1. Remove redundant cleanup script (we have cleanup-workspace.sh)
if [ -f "cleanup.sh" ]; then
    echo "Removing redundant cleanup.sh (replaced by cleanup-workspace.sh)..."
    rm -f cleanup.sh
    echo "✅ Removed cleanup.sh"
fi

# 2. Create docs archive directory
if [ ! -d "docs/archive" ]; then
    mkdir -p docs/archive
    echo "✅ Created docs/archive directory"
fi

# 3. Move historical documentation to archive
echo ""
echo "Archiving historical documentation..."
HISTORICAL_DOCS=(
    "CLEANUP_SUMMARY.md"
    "FOLDER_RENAME_SUMMARY.md"
    "WORKSPACE_REORGANIZATION.md"
)

for doc in "${HISTORICAL_DOCS[@]}"; do
    if [ -f "$doc" ]; then
        mv "$doc" "docs/archive/"
        echo "  ✅ Archived $doc"
    fi
done

# 4. Move THREAT_ENGINE_IMPLEMENTATION to threat-engine folder
if [ -f "THREAT_ENGINE_IMPLEMENTATION.md" ]; then
    if [ -d "threat-engine" ]; then
        mv "THREAT_ENGINE_IMPLEMENTATION.md" "threat-engine/IMPLEMENTATION.md"
        echo "  ✅ Moved THREAT_ENGINE_IMPLEMENTATION.md to threat-engine/"
    fi
fi

echo ""
echo "=== Files to Update Manually ==="
echo ""
echo "The following files need manual updates (outdated references):"
echo "  1. build-and-push-engines.sh - Update folder names"
echo "  2. test-engines-local.sh - Update paths"
echo "  3. deploy-all-engines.sh - Review and update if needed"
echo "  4. rebuild-and-redeploy.sh - Review and update if needed"
echo ""
echo "=== Cleanup Complete ==="
