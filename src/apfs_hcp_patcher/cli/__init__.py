"""CLI interface for the APFS HCP patcher."""

from __future__ import annotations

from ..app import run


def apfs_hcp_patcher(argv: list[str] | None = None) -> None:
    """Run the public CLI wrapper."""
    run(argv)
