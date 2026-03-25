"""CLI interface for the APFS HCP patcher."""

from __future__ import annotations

import argparse

from .. import __version__
from ..patch import PatchError, patch_file


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="apfs-hcp-patcher",
        description="Patch APFS.kext or kernelcache.decompressed to allow HCP snapshot delta restores.",
    )
    parser.add_argument(
        "-f", "--force", action="store_true", help="Overwrite the output if it exists."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("input", help="Input APFS Mach-O or kernelcache.decompressed")
    parser.add_argument("output", nargs="?", help="Output path (default: <input>.patched)")
    return parser


def apfs_hcp_patcher(argv: list[str] | None = None) -> None:
    """Run the command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = patch_file(args.input, args.output, force=args.force)
    except (FileNotFoundError, FileExistsError, PatchError) as exc:
        parser.exit(1, f"error: {exc}\n")

    location = result.location
    if location.fileset_entry is not None:
        print(f"detected MH_FILESET; using fileset entry {location.fileset_entry}")

    print(
        f"symbol: {location.symbol_name} @ 0x{location.symbol_address:x} "
        f"[0x{location.symbol_offset:x}]"
    )

    if result.already_patched:
        print("file is already patched")
        return

    print(f"patch: 0x{location.patch_address:x} [0x{location.patch_offset:x}]")
    print(f"  {location.original_instruction:08x} -> {location.replacement_instruction:08x}")
    print(f"wrote: {result.output_path}")
