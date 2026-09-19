"""
Connectors Health & Pipeline Diagnostic Command
Usage:
    python -m connectors.diagnostic
"""

import sys
from pathlib import Path

# Add repo root and apps/api to sys.path
root_dir = Path(__file__).resolve().parent.parent
apps_api = root_dir / "apps" / "api"
for p in [str(root_dir), str(apps_api)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from diagnose_connectors import run_diagnostics

if __name__ == "__main__":
    run_diagnostics()
