"""Cybersecurity OSINT Intelligence Platform Backend API Application Package."""

import sys
from pathlib import Path

# Ensure cyber-osint repository root is on sys.path
_repo_root = Path(__file__).resolve().parent.parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

__version__ = "0.1.0"
