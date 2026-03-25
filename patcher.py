#!/usr/bin/env python3
"""Compatibility wrapper for the packaged CLI."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
    from apfs_hcp_patcher.cli import apfs_hcp_patcher

    apfs_hcp_patcher()


if __name__ == "__main__":
    main()
