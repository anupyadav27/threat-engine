#!/bin/bash
# Cleanup unwanted files from workspace

set -e

WORKSPACE_ROOT="/Users/apple/Desktop/threat-engine"
cd "$WORKSPACE_ROOT"

echo "=== Cleaning Workspace ==="
echo ""

# 1. Remove Python cache files
echo "1. Removing Python cache files..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "*.pyo" -delete 2>/dev/null || true
echo "   ✅ Python cache cleaned"

# 2. Remove .DS_Store files
echo "2. Removing .DS_Store files..."
find . -name ".DS_Store" -delete 2>/dev/null || true
echo "   ✅ .DS_Store files removed"

# 3. Remove backup files
echo "3. Removing backup files..."
find . -name "*.bak" -delete 2>/dev/null || true
find . -name "*.backup" -delete 2>/dev/null || true
find . -name "*~" -delete 2>/dev/null || true
find . -name "*.swp" -delete 2>/dev/null || true
find . -name "*.swo" -delete 2>/dev/null || true
echo "   ✅ Backup files removed"

# 4. Remove temporary files
echo "4. Removing temporary files..."
find . -name "*.tmp" -delete 2>/dev/null || true
find . -name "*.temp" -delete 2>/dev/null || true
echo "   ✅ Temporary files removed"

# 5. Remove old reorganization scripts
echo "5. Removing old cleanup/reorganize scripts..."
rm -f reorganize_engines.sh 2>/dev/null || true
rm -f cleanup-oregon-resources.sh 2>/dev/null || true
echo "   ✅ Old scripts removed"

# 6. Remove .pytest_cache
echo "6. Removing pytest cache..."
find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
echo "   ✅ Pytest cache removed"

# 7. Remove .mypy_cache
echo "7. Removing mypy cache..."
find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
echo "   ✅ Mypy cache removed"

# 8. Remove .coverage files
echo "8. Removing coverage files..."
find . -name ".coverage" -delete 2>/dev/null || true
find . -name "htmlcov" -type d -exec rm -rf {} + 2>/dev/null || true
echo "   ✅ Coverage files removed"

# 9. Remove node_modules if any
echo "9. Checking for node_modules..."
if [ -d "node_modules" ]; then
    rm -rf node_modules
    echo "   ✅ node_modules removed"
else
    echo "   ℹ️  No node_modules found"
fi

# 10. Remove .idea and .vscode if not needed
echo "10. Checking IDE directories..."
if [ -d ".idea" ]; then
    echo "   ℹ️  .idea directory found (keeping for now)"
fi
if [ -d ".vscode" ]; then
    echo "   ℹ️  .vscode directory found (keeping for now)"
fi

echo ""
echo "=== Cleanup Complete ==="
echo ""
echo "Remaining workspace size:"
du -sh "$WORKSPACE_ROOT" 2>/dev/null || echo "   (size check skipped)"

# 11. Remove old CSV backup files (keep only the latest)
echo "11. Cleaning old CSV backup files..."
cd compliance
# Keep only the most recent consolidated rules file
ls -t consolidated_rules_phase4_*.csv consolidated_compliance_rules_*.csv 2>/dev/null | tail -n +2 | xargs rm -f 2>/dev/null || true
cd ..
echo "   ✅ Old CSV backups removed (kept latest)"

# 12. Remove empty directories
echo "12. Removing empty directories..."
find . -type d -empty -not -path "*/\.*" -not -path "*/engines-output/*" -delete 2>/dev/null || true
echo "   ✅ Empty directories removed"

# 13. Remove old reporting directories
echo "13. Cleaning old reporting directories..."
find configScan_engines -type d -path "*/reporting/reporting_*" -exec rm -rf {} + 2>/dev/null || true
echo "   ✅ Old reporting directories removed"

# 14. Remove old test output files
echo "14. Cleaning test output files..."
find . -name "*.log" -not -path "*/\.*" -not -path "*/node_modules/*" -delete 2>/dev/null || true
echo "   ✅ Test log files removed"

echo ""
echo "=== Final Cleanup Summary ==="
