"""
Main entry point for SQL Injection Assessment Framework.
Allows running: python -m sqlprobe
"""

import sys
from . import main

if __name__ == "__main__":
    sys.exit(main())