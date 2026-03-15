#!/bin/bash

# Cleanup Script: Remove Legacy Documentation and Files
# This script removes development-phase documentation and redundant files

BACKUP_DIR="/Users/apple/Desktop/threat-engine-legacy-backup-$(date +%Y%m%d)"

echo "======================================================================="
echo "LEGACY FILE CLEANUP"
echo "======================================================================="
echo ""
echo "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# Step 1: Backup then remove legacy markdown docs at root
echo ""
echo "Step 1: Backing up and removing legacy markdown documentation..."
echo "-----------------------------------------------------------------------"

# List of large legacy docs to remove (keep README, CHANGELOG, CONTRIBUTING, LICENSE)
legacy_docs=(
    "DISCOVERIES_ENGINE_FLOW_DOCUMENTATION.md"
    "DISCOVERIES_ENGINE_COMPLETE_ANALYSIS.md"
    "DISCOVERIES_ENGINE_CODE_ANALYSIS.md"
    "DISCOVERIES_ENGINE_ORCHESTRATION_IMPLEMENTATION.md"
    "DISCOVERIES_REFACTORING_PLAN.md"
    "DISCOVERY_DATA_COMPARISON_ANALYSIS.md"
    "PYTHONSDK_DATABASE_VERIFIED.md"
    "DATABASE_EXPORT_ANALYSIS.md"
    "API_INTEGRATION_ANALYSIS.md"
    "ENGINE_DATABASE_QUERY_ANALYSIS.md"
    "ENGINE_METADATA_FLOW_REQUIREMENTS.md"
    "METADATA_FLOW_COMPLETE.md"
)

cd /Users/apple/Desktop/threat-engine

removed_count=0
for doc in "${legacy_docs[@]}"; do
    if [ -f "$doc" ]; then
        echo "  Moving: $doc"
        mv "$doc" "$BACKUP_DIR/"
        removed_count=$((removed_count + 1))
    fi
done

echo "  ✅ Removed $removed_count legacy documentation files"

# Step 2: Backup then remove data_pythonsdk analysis files
echo ""
echo "Step 2: Removing analysis files from data_pythonsdk..."
echo "-----------------------------------------------------------------------"

mkdir -p "$BACKUP_DIR/data_pythonsdk"
find data_pythonsdk -name "*SUMMARY.md" -o -name "*ANALYSIS.md" 2>/dev/null | while read -r file; do
    if [ -f "$file" ]; then
        echo "  Moving: $file"
        mkdir -p "$BACKUP_DIR/$(dirname "$file")"
        mv "$file" "$BACKUP_DIR/$file"
    fi
done

echo "  ✅ Removed analysis files from data_pythonsdk"

# Step 3: Backup then remove legacy migration scripts
echo ""
echo "Step 3: Removing legacy migration scripts..."
echo "-----------------------------------------------------------------------"

mkdir -p "$BACKUP_DIR/scripts"
legacy_scripts=(
    "scripts/migrate_discoveries_to_check_db.py"
    "scripts/compare_discovery_sources.py"
    "scripts/regenerate_comprehensive_discovery_yamls.py"
    "scripts/validate_check_discovery_alignment.py"
)

for script in "${legacy_scripts[@]}"; do
    if [ -f "$script" ]; then
        echo "  Moving: $script"
        mv "$script" "$BACKUP_DIR/$script"
    fi
done

echo "  ✅ Removed legacy migration scripts"

# Step 4: Optionally archive database_exports
echo ""
echo "Step 4: Archiving database_exports..."
echo "-----------------------------------------------------------------------"

if [ -d "database_exports" ]; then
    echo "  Creating compressed archive..."
    tar -czf "$BACKUP_DIR/database_exports.tar.gz" database_exports/
    echo "  Removing database_exports directory..."
    rm -rf database_exports/
    echo "  ✅ Archived and removed database_exports"
else
    echo "  (database_exports not found, skipping)"
fi

# Summary
echo ""
echo "======================================================================="
echo "CLEANUP COMPLETE"
echo "======================================================================="
echo ""
echo "Backup location: $BACKUP_DIR"
echo ""
echo "Files moved to backup:"
ls -lh "$BACKUP_DIR" | head -20
echo ""
echo "Next steps:"
echo "  1. Review backup directory to ensure nothing important was removed"
echo "  2. Run: git status to see changes"
echo "  3. Commit the cleanup"
echo "  4. After 30 days, can delete backup if not needed"
