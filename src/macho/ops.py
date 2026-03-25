"""File-level Mach-O operations."""

from __future__ import annotations

import os
import mmap  # noqa: TC003
import shutil
import subprocess
from pathlib import Path

from ._spec import FAT_CIGAM, FAT_CIGAM_64, FAT_MAGIC, FAT_MAGIC_64, U32_STRUCT


def read_u32(buf: bytes | bytearray | mmap.mmap, offset: int) -> int:
    """Read a little-endian uint32 from a bytes-like buffer."""
    return U32_STRUCT.unpack_from(buf, offset)[0]


def is_universal(path: str | os.PathLike[str]) -> bool:
    """Return whether a path points at a FAT/universal Mach-O."""
    with open(path, "rb") as handle:
        magic = int.from_bytes(handle.read(4), "big")
    return magic in {FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64}


def thin_arm64e(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    force: bool = False,
) -> None:
    """Extract the arm64e slice using `lipo`."""
    destination = Path(output_path)
    if destination.exists() and not force:
        raise FileExistsError(f"output file '{destination}' already exists")

    subprocess.run(
        ["lipo", os.fspath(input_path), "-thin", "arm64e", "-output", os.fspath(output_path)],
        check=True,
    )


def copy_and_write_u32(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    patch_offset: int,
    value: int,
) -> None:
    """Copy a file if needed and patch a single uint32 value."""
    if os.fspath(input_path) != os.fspath(output_path):
        shutil.copyfile(input_path, output_path)

    with open(output_path, "r+b") as handle:
        handle.seek(patch_offset)
        handle.write(U32_STRUCT.pack(value))


def ad_hoc_codesign(path: str | os.PathLike[str]) -> None:
    """Apply an ad-hoc code signature."""
    subprocess.run(["codesign", "-f", "-s", "-", os.fspath(path)], check=True)
