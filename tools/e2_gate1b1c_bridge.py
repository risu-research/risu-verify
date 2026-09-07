#!/usr/bin/env python3
from __future__ import annotations

"""Repository-local bootstrap for the Gate1B/1C production bridge CLI."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from risu_e2_semantic.bridge_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
