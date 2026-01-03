#!/usr/bin/env python3
"""
Direct runner for yaml-rule-builder
Can be run as: python3 run.py <command> [args]
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from cli import main

if __name__ == '__main__':
    main()

