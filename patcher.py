#!/usr/bin/env python3
"""Patch APFS HCP snapshot delta restore check for any recent macOS

The check is implemented in APFS.kext in `delta_restore_verify_compatibility`:

```
0xXXXXXX00:  ldr   w8, [x20, #8]       ; load encryption type
0xXXXXXXX4:  cmp   w8, #3              ; compare with HCP type (3)
0xXXXXXXX8:  b.ne  loc_XXXXX           ; if NOT HCP, branch to success
```

The patcher locates this code and overwrites the conditional branching with
unconditional:

```
0xXXXXXXX8:  b     loc_XXXXX           ; branch to success unconditionally
```

By default patcher attempts to use [lief](https://github.com/lief-project/LIEF)
in order to parse Mach-O structures and locate the patch target with more precision.

Unfortunately, lief has issues with parsing recent kernelcaches, theferore, in this
case or when enforced via `--dumb`, whole-file pattern matching is performed, which
in theory may result in invalid patching. On practice, however,  it should be safe
because the pattern is unique enough.
"""

import os
import sys
import mmap
import shutil
import struct
import argparse
import importlib
from bisect import bisect_right
from collections.abc import Iterable  # noqa: TC003
from dataclasses import dataclass
from typing import Any

type SegmentEntry = tuple[int, int, int]  # (start, end, base)
type FileRange = tuple[int, int]  # (start, end)

FUNC_NAME = "_delta_restore_verify_compatibility"
PATTERN = b"\x88\x0a\x40\xb9\x1f\x0d\x00\x71"
PATTERN_LEN = len(PATTERN)
B_NE_MASK, B_NE_MATCH = 0xFF00001F, 0x54000001
B_MASK, B_MATCH = 0xFC000000, 0x14000000
DEFAULT_FUNC_SCAN_SIZE = 0x200
MAX_FUNC_SCAN_SIZE = 0x400
MACH_HEADER_SIZE = 16
HEADER_STRUCT = struct.Struct("<IIII")
U32_STRUCT = struct.Struct("<I")

# Mach-O constants
MH_MAGIC_64 = 0xFEEDFACF
MH_FILESET = 0xC


@dataclass(slots=True)
class MachOContext:
    """Fast lookup tables derived from a LIEF Mach-O object."""

    symbol_values: list[int]
    symbol_by_name: dict[str, int]
    virtual_segments: list[SegmentEntry]
    file_segments: list[SegmentEntry]

    @classmethod
    def from_macho(cls, macho: Any) -> MachOContext:
        symbols = [symbol.value for symbol in macho.symbols if symbol.value]
        return cls(
            symbol_values=sorted(symbols),
            symbol_by_name={symbol.name: symbol.value for symbol in macho.symbols if symbol.value},
            virtual_segments=[
                (
                    seg.virtual_address,
                    seg.virtual_address + seg.virtual_size,
                    seg.file_offset,
                )
                for seg in macho.segments
                if seg.virtual_size > 0 and seg.file_size > 0
            ],
            file_segments=[
                (
                    seg.file_offset,
                    seg.file_offset + seg.file_size,
                    seg.virtual_address,
                )
                for seg in macho.segments
                if seg.virtual_size > 0 and seg.file_size > 0
            ],
        )

    def function_range(self, name: str) -> tuple[int, int] | None:
        """Find function by symbol name and return (address, scan_size)."""
        addr = self.symbol_by_name.get(name)
        if addr is None:
            return None
        next_idx = bisect_right(self.symbol_values, addr)
        next_addr = (
            self.symbol_values[next_idx]
            if next_idx < len(self.symbol_values)
            else addr + DEFAULT_FUNC_SCAN_SIZE
        )
        return addr, min(next_addr - addr, MAX_FUNC_SCAN_SIZE)

    def merged_file_ranges(self) -> list[FileRange]:
        """Build sorted, merged file offset ranges covered by segments."""
        ranges = sorted((start, end) for start, end, _ in self.file_segments)
        merged: list[list[int]] = []
        for start, end in ranges:
            if not merged or start > merged[-1][1]:
                merged.append([start, end])
            elif end > merged[-1][1]:
                merged[-1][1] = end
        return [(start, end) for start, end in merged]

    def vaddr_to_off(self, vaddr: int) -> int | None:
        """Convert virtual address to file offset."""
        for start, end, file_offset in self.virtual_segments:
            if start <= vaddr < end:
                return vaddr - start + file_offset
        return None

    def off_to_vaddr(self, off: int) -> int | None:
        """Convert file offset to virtual address."""
        for start, end, virtual_address in self.file_segments:
            if start <= off < end:
                return off - start + virtual_address
        return None


def is_fileset(mm: mmap.mmap) -> bool:
    """Check if file is a kernelcache (MH_FILESET) - lief is slow on these."""
    if len(mm) < MACH_HEADER_SIZE:
        return False
    magic, _, _, filetype = HEADER_STRUCT.unpack_from(mm)
    return magic == MH_MAGIC_64 and filetype == MH_FILESET


def b_cond_to_b(instr: int) -> int:
    """Convert conditional branch to unconditional branch."""
    imm19 = (instr >> 5) & 0x7FFFF
    return 0x14000000 | (imm19 | (0x3F80000 if imm19 & 0x40000 else 0))


def is_b(instr: int) -> bool:
    """Check if instruction is B (unconditional branch)."""
    return (instr & B_MASK) == B_MATCH


def is_patch_branch(instr: int) -> bool:
    """Check if instruction is the expected B.NE or an already-patched B."""
    return (instr & B_NE_MASK) == B_NE_MATCH or is_b(instr)


def read_u32(buf: mmap.mmap, offset: int) -> int:
    """Read a little-endian uint32 from a buffer."""
    return U32_STRUCT.unpack_from(buf, offset)[0]


def find_pattern(mm: mmap.mmap, start: int = 0, end: int | None = None) -> int | None:
    """Find pattern and return offset of the following branch instruction."""
    end = len(mm) if end is None else min(end, len(mm))
    unpack = U32_STRUCT.unpack_from
    find = mm.find
    pos = start
    while (pos := find(PATTERN, pos, end)) != -1:
        branch_off = pos + PATTERN_LEN
        if branch_off + U32_STRUCT.size <= end and is_patch_branch(unpack(mm, branch_off)[0]):
            return branch_off
        pos += 4
    return None


def find_pattern_ranges(mm: mmap.mmap, ranges: Iterable[FileRange]) -> int | None:
    """Find pattern in one or more file ranges."""
    for start, end in ranges:
        patch_off = find_pattern(mm, start, end)
        if patch_off is not None:
            return patch_off
    return None


def scan_for_patch(mm: mmap.mmap, macho: MachOContext | None) -> tuple[int, int, int | None]:
    """Scan file for patch location.

    Uses a three-tier search when Mach-O metadata is available:
      1. Symbol-scoped: search only within the target function's bounds.
      2. Segment-scoped: search within merged mapped segment ranges.
      3. Whole-file: brute-force fallback.

    Returns (file_offset, instruction, virtual_address) or exits on failure.
    """
    patch_off: int | None = None
    patch_vaddr: int | None = None

    if macho:
        # Tier 1: symbol-scoped search
        func = macho.function_range(FUNC_NAME)
        if func:
            vaddr, size = func
            off = macho.vaddr_to_off(vaddr)
            if off is not None:
                print(f"symbol: {FUNC_NAME} @ 0x{vaddr:x} [0x{off:x}]")
                patch_off = find_pattern(mm, off, off + size)
                if patch_off is not None:
                    patch_vaddr = vaddr + (patch_off - off)

        # Tier 2: segment-scoped search
        if patch_off is None:
            print("symbol miss, searching mapped segments")
            patch_off = find_pattern_ranges(mm, macho.merged_file_ranges())
            if patch_off is not None:
                patch_vaddr = macho.off_to_vaddr(patch_off)

    # Tier 3: whole-file fallback
    if patch_off is None:
        if macho:
            print("segment scan miss, searching file")
        patch_off = find_pattern(mm)
        if patch_off is not None and macho:
            patch_vaddr = macho.off_to_vaddr(patch_off)

    if patch_off is None:
        sys.exit("pattern not found")

    return patch_off, read_u32(mm, patch_off), patch_vaddr


def load_macho(inp: str, dumb: bool) -> MachOContext | None:
    """Load Mach-O metadata via LIEF when available and allowed."""
    if dumb:
        return None

    try:
        lief = importlib.import_module("lief")
    except ImportError:
        print("WARNING: lief dependency is unavailable", file=sys.stderr)
        return None

    binary = lief.MachO.parse(inp)
    if not binary:
        return None

    macho = binary.at(0)
    print(f"{inp}:")
    print(macho.header)
    return MachOContext.from_macho(macho)


def write_patch(inp: str, out: str, patch_off: int, new: int) -> None:
    """Copy the input if needed and write the patched instruction."""
    if inp != out:
        shutil.copyfile(inp, out)

    with open(out, "r+b") as f:
        f.seek(patch_off)
        f.write(U32_STRUCT.pack(new))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dumb", action="store_true", help="Enable dumb mode")
    parser.add_argument("-f", "--force", action="store_true", help="Overwrite output if exists")
    parser.add_argument("input", help="Input file")
    parser.add_argument("output", nargs="?", help="Output file")
    args = parser.parse_args()

    inp: str = args.input
    out: str = args.output if args.output else f"{inp}.patched"
    dumb: bool = args.dumb

    with open(inp, "rb") as f:
        if os.fstat(f.fileno()).st_size == 0:
            sys.exit("input file is empty")

        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # Early kernelcache detection before slow lief parsing.
            if not dumb and is_fileset(mm):
                print("detected Mach-O is MH_FILESET")
                dumb = True

            macho = load_macho(inp, dumb)
            if not macho:
                print("falling back to dumb pattern search")

            patch_off, old, vaddr = scan_for_patch(mm, macho)

    # Check if already patched (exit early)
    if is_b(old):
        print("file is already patched")
        sys.exit(0)

    # Check if output exists
    if os.path.exists(out) and not args.force:
        sys.exit(f"output file '{out}' already exists (use -f to overwrite)")

    new = b_cond_to_b(old)
    write_patch(inp, out, patch_off, new)

    print(f"patch: 0x{vaddr:x} [0x{patch_off:x}]" if vaddr else f"patch: [0x{patch_off:x}]")
    print(f"  {old:08x} -> {new:08x}")
    print(f"wrote: {out}")


if __name__ == "__main__":
    main()
