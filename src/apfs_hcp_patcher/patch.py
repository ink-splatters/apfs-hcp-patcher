"""APFS patch logic."""

from __future__ import annotations

import mmap
from dataclasses import dataclass
from pathlib import Path

from macho import (
    MachOContext,
    MachOError,
    copy_and_write_u32,
    is_fileset_image,
    load_fileset_macho,
    load_standalone_macho,
    read_u32,
)

APFS_FILESET_ENTRY = "com.apple.filesystems.apfs"
FUNCTION_NAME = "_delta_restore_verify_compatibility"
PATTERN = b"\x88\x0a\x40\xb9\x1f\x0d\x00\x71"
PATTERN_LEN = len(PATTERN)

B_NE_MASK = 0xFF00001F
B_NE_MATCH = 0x54000001
B_MASK = 0xFC000000
B_MATCH = 0x14000000


class PatchError(ValueError):
    """Raised when the APFS patch cannot be located or applied."""


@dataclass(slots=True)
class PatchLocation:
    """Resolved location of the APFS patch site."""

    symbol_name: str
    symbol_address: int
    symbol_offset: int
    patch_address: int
    patch_offset: int
    original_instruction: int
    replacement_instruction: int
    fileset_entry: str | None = None


@dataclass(slots=True)
class PatchResult:
    """Result of applying or verifying the APFS patch."""

    output_path: Path
    location: PatchLocation
    already_patched: bool = False


def b_cond_to_b(instruction: int) -> int:
    """Convert a conditional branch to an unconditional branch."""
    imm19 = (instruction >> 5) & 0x7FFFF
    return B_MATCH | (imm19 | (0x3F80000 if imm19 & 0x40000 else 0))


def is_b(instruction: int) -> bool:
    """Return whether the instruction is an unconditional branch."""
    return (instruction & B_MASK) == B_MATCH


def is_patch_branch(instruction: int) -> bool:
    """Return whether the instruction is the expected patch target."""
    return (instruction & B_NE_MASK) == B_NE_MATCH or is_b(instruction)


def find_pattern_hits(mm: bytes | bytearray | mmap.mmap, start: int, end: int) -> list[int]:
    """Find candidate branch offsets following the known APFS pattern."""
    unpack_u32 = read_u32
    search_end = min(end, len(mm))
    offset = start
    hits: list[int] = []
    while (offset := mm.find(PATTERN, offset, search_end)) != -1:
        branch_offset = offset + PATTERN_LEN
        if branch_offset + 4 <= search_end and is_patch_branch(unpack_u32(mm, branch_offset)):
            hits.append(branch_offset)
        offset += 4
    return hits


def locate_patch(mm: mmap.mmap) -> PatchLocation:
    """Locate the exact APFS patch site inside the input image."""
    context, fileset_entry = _load_target_context(mm)
    function_range = context.function_range(FUNCTION_NAME)
    if function_range is None:
        raise PatchError(f"required symbol not found: {FUNCTION_NAME}")

    symbol_address, scan_size = function_range
    symbol_offset = context.vaddr_to_off(symbol_address)
    if symbol_offset is None:
        raise PatchError(f"could not map symbol to file offset: {FUNCTION_NAME}")

    hits = find_pattern_hits(mm, symbol_offset, symbol_offset + scan_size)
    if len(hits) != 1:
        raise PatchError(f"expected exactly one patch site in {FUNCTION_NAME}, found {len(hits)}")

    patch_offset = hits[0]
    original_instruction = read_u32(mm, patch_offset)
    return PatchLocation(
        symbol_name=FUNCTION_NAME,
        symbol_address=symbol_address,
        symbol_offset=symbol_offset,
        patch_address=symbol_address + (patch_offset - symbol_offset),
        patch_offset=patch_offset,
        original_instruction=original_instruction,
        replacement_instruction=b_cond_to_b(original_instruction),
        fileset_entry=fileset_entry,
    )


def patch_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    *,
    force: bool = False,
) -> PatchResult:
    """Patch a standalone APFS Mach-O or a kernelcache container."""
    source = Path(input_path)
    destination = (
        Path(output_path) if output_path is not None else source.with_name(f"{source.name}.patched")
    )

    if not source.exists():
        raise FileNotFoundError(f"input file '{source}' does not exist")

    with source.open("rb") as handle:
        if source.stat().st_size == 0:
            raise PatchError("input file is empty")
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            location = locate_patch(mm)

    if is_b(location.original_instruction):
        return PatchResult(output_path=destination, location=location, already_patched=True)

    if destination.exists() and not force:
        raise FileExistsError(f"output file '{destination}' already exists (use -f to overwrite)")

    copy_and_write_u32(
        source,
        destination,
        location.patch_offset,
        location.replacement_instruction,
    )
    return PatchResult(output_path=destination, location=location, already_patched=False)


def _load_target_context(mm: mmap.mmap) -> tuple[MachOContext, str | None]:
    try:
        if is_fileset_image(mm):
            return load_fileset_macho(mm, APFS_FILESET_ENTRY), APFS_FILESET_ENTRY
        return load_standalone_macho(mm), None
    except MachOError as exc:
        raise PatchError(str(exc)) from exc
