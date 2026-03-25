"""APFS HCP snapshot delta restore patcher."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .patch import PatchError, PatchLocation, PatchResult, patch_file

try:
    __version__ = version("apfs-hcp-patcher")
except PackageNotFoundError:
    __version__ = "dev"

__all__ = [
    "PatchError",
    "PatchLocation",
    "PatchResult",
    "__version__",
    "patch_file",
]
