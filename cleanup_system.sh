#!/bin/bash

# System Cleanup Script
# This script removes cache files, Python artifacts, and other unnecessary files

set -e

echo "🧹 Starting System Cleanup..."
echo ""

# Count before cleanup
PYCACHE_COUNT=$(find ~ -type d -name "__pycache__" 2>/dev/null | wc -l | tr -d ' ')
PYC_COUNT=$(find ~ -type f \( -name "*.pyc" -o -name "*.pyo" -o -name "*.pyd" \) 2>/dev/null | wc -l | tr -d ' ')
DSSTORE_COUNT=$(find ~ -type f -name ".DS_Store" 2>/dev/null | wc -l | tr -d ' ')

echo "📊 Before cleanup:"
echo "   __pycache__ directories: $PYCACHE_COUNT"
echo "   .pyc/.pyo files: $PYC_COUNT"
echo "   .DS_Store files: $DSSTORE_COUNT"
echo ""

# 1. Remove all __pycache__ directories
echo "🗑️  Removing __pycache__ directories..."
find ~ -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
echo "   ✓ Removed __pycache__ directories"

# 2. Remove all .pyc, .pyo, .pyd files
echo "🗑️  Removing .pyc/.pyo/.pyd files..."
find ~ -type f \( -name "*.pyc" -o -name "*.pyo" -o -name "*.pyd" \) -delete 2>/dev/null || true
echo "   ✓ Removed Python cache files"

# 3. Remove .DS_Store files
echo "🗑️  Removing .DS_Store files..."
find ~ -type f -name ".DS_Store" -delete 2>/dev/null || true
echo "   ✓ Removed .DS_Store files"

# 4. Remove .pytest_cache directories
echo "🗑️  Removing .pytest_cache directories..."
find ~ -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
echo "   ✓ Removed .pytest_cache directories"

# 5. Remove .mypy_cache directories
echo "🗑️  Removing .mypy_cache directories..."
find ~ -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
echo "   ✓ Removed .mypy_cache directories"

# 6. Remove .ruff_cache directories
echo "🗑️  Removing .ruff_cache directories..."
find ~ -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
echo "   ✓ Removed .ruff_cache directories"

# 7. Clean pip cache
echo "🗑️  Cleaning pip cache..."
pip cache purge 2>/dev/null || python3 -m pip cache purge 2>/dev/null || true
echo "   ✓ Cleaned pip cache"

# 8. Clean Google Chrome cache (if exists)
if [ -d ~/Library/Caches/Google ]; then
    echo "🗑️  Cleaning Google cache (keeping structure)..."
    find ~/Library/Caches/Google -type f -mtime +30 -delete 2>/dev/null || true
    echo "   ✓ Cleaned old Google cache files"
fi

# 9. Clean Homebrew cache (old downloads)
echo "🗑️  Cleaning Homebrew cache..."
brew cleanup --prune=all 2>/dev/null || true
echo "   ✓ Cleaned Homebrew cache"

# 10. Clean Trivy cache (if exists)
if [ -d ~/Library/Caches/trivy ]; then
    echo "🗑️  Cleaning Trivy cache..."
    rm -rf ~/Library/Caches/trivy/* 2>/dev/null || true
    echo "   ✓ Cleaned Trivy cache"
fi

# 11. Clean Comet cache (if exists)
if [ -d ~/Library/Caches/Comet ]; then
    echo "🗑️  Cleaning Comet cache..."
    find ~/Library/Caches/Comet -type f -mtime +7 -delete 2>/dev/null || true
    echo "   ✓ Cleaned Comet cache"
fi

# 12. Clean node-gyp cache
if [ -d ~/Library/Caches/node-gyp ]; then
    echo "🗑️  Cleaning node-gyp cache..."
    rm -rf ~/Library/Caches/node-gyp/* 2>/dev/null || true
    echo "   ✓ Cleaned node-gyp cache"
fi

# 13. Clean Python cache
if [ -d ~/Library/Caches/com.apple.python ]; then
    echo "🗑️  Cleaning Python cache..."
    rm -rf ~/Library/Caches/com.apple.python/* 2>/dev/null || true
    echo "   ✓ Cleaned Python cache"
fi

# 14. Clean .cache directory
if [ -d ~/.cache ]; then
    echo "🗑️  Cleaning ~/.cache..."
    find ~/.cache -type f -mtime +30 -delete 2>/dev/null || true
    echo "   ✓ Cleaned ~/.cache"
fi

echo ""
echo "✅ Cleanup completed!"
echo ""
echo "💡 Recommendations:"
echo "   1. Review and remove unused virtual environments manually"
echo "   2. Consider removing old node_modules from unused projects"
echo "   3. Clean up old Cursor worktrees if not needed"
echo ""
echo "To see virtual environments: find ~ -type d -name 'venv' -o -name '.venv'"
echo "To see node_modules: find ~ -type d -name 'node_modules'"
