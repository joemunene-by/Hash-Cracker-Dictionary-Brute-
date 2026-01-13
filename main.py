#!/usr/bin/env python3
"""
Hash Cracker Tool - Main Entry Point

Professional hash-cracking and password auditing framework for
defensive security, forensics, and compliance testing.

Copyright (c) 2026 Hash Cracker Tool
Licensed under Apache License 2.0
"""

import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from cli.interface import main

if __name__ == '__main__':
    main()
