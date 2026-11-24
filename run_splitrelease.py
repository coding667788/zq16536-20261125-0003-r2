#!/usr/bin/env python3
"""Repository-root launcher usable with ``python -I run_splitrelease.py``.

Isolated Python can omit the script directory from ``sys.path`` in safe-path
mode, so insert this trusted launcher's own directory explicitly.  The current
working directory is deliberately not added.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from splitrelease.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
