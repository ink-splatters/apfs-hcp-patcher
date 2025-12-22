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
from typing import Any

FUNC_NAME = "_delta_restore_verify_compatibility"
PATTERN = b"\x88\x0a\x40\xb9\x1f\x0d\x00\x71"
B_NE_MASK, B_NE_MATCH = 0xFF00001F, 0x54000001
B_MASK, B_MATCH = 0xFC000000, 0x14000000

# Mach-O constants
MH_MAGIC_64 = 0xFEEDFACF
MH_FILESET = 0xC


def is_fileset(path: str) -> bool:
    """Check if file is a kernelcache (MH_FILESET) - lief is slow on these."""

    with open(path, "rb") as f:
        header = f.read(16)
    if len(header) < 16:
        return False
    magic, _, _, filetype = struct.unpack("<IIII", header)
    return magic == MH_MAGIC_64 and filetype == MH_FILESET


def b_cond_to_b(instr: int) -> int:
    """Convert conditional branch to unconditional branch."""
    imm19 = (instr >> 5) & 0x7FFFF
    return 0x14000000 | (imm19 | (0x3F80000 if imm19 & 0x40000 else 0))


def is_b(instr: int) -> bool:
    """Check if instruction is B (unconditional branch)."""
    return (instr & B_MASK) == B_MATCH


def find_pattern(mm: mmap.mmap, start: int = 0, end: int | None = None) -> int | None:
    """Find pattern and return offset of the following branch instruction."""
    end = end or len(mm)
    pos = start
    while (pos := mm.find(PATTERN, pos, end)) != -1:
        if pos + 12 <= end:
            instr = struct.unpack_from("<I", mm, pos + 8)[0]
            # Match B.NE (unpatched) or B (already patched)
            if (instr & B_NE_MASK) == B_NE_MATCH or is_b(instr):
                return pos + 8
        pos += 4
    return None


def find_func(macho: Any, name: str) -> tuple[int, int] | None:
    """Find function by name and return (address, size)."""
    syms = sorted(((s.value, s.name) for s in macho.symbols if s.value), key=lambda x: x[0])
    for i, (addr, n) in enumerate(syms):
        if n == name:
            return addr, min((syms[i + 1][0] - addr) if i + 1 < len(syms) else 0x200, 0x400)
    return None


def vaddr_to_off(macho: Any, vaddr: int) -> int | None:
    """Convert virtual address to file offset."""
    for seg in macho.segments:
        if seg.virtual_address <= vaddr < seg.virtual_address + seg.virtual_size:
            return vaddr - seg.virtual_address + seg.file_offset
    return None


def off_to_vaddr(macho: Any, off: int) -> int | None:
    """Convert file offset to virtual address."""
    for seg in macho.segments:
        if seg.file_offset <= off < seg.file_offset + seg.file_size:
            return off - seg.file_offset + seg.virtual_address
    return None


def scan_for_patch(inp: str, macho: Any | None) -> tuple[int, int]:
    """Scan file for patch location. Returns (offset, instruction) or exits."""
    with open(inp, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            patch_off: int | None = None

            if macho:
                func = find_func(macho, FUNC_NAME)
                if func:
                    vaddr, sz = func
                    off = vaddr_to_off(macho, vaddr)
                    if off:
                        print(f"symbol: {FUNC_NAME} @ 0x{vaddr:x} [0x{off:x}]")
                        patch_off = find_pattern(mm, off, off + sz)
                if patch_off is None:
                    print("symbol miss, searching file")

            if patch_off is None:
                patch_off = find_pattern(mm)

            if patch_off is None:
                sys.exit("pattern not found")

            assert patch_off is not None  # type narrowing for sys.exit NoReturn
            old = struct.unpack_from("<I", mm, patch_off)[0]
            return patch_off, old
        finally:
            mm.close()


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

    # Early kernelcache detection before slow lief parsing
    if not dumb and is_fileset(inp):
        print("detected Mach-O is MH_FILESET")
        dumb = True

    lief = None
    macho = None

    if not dumb:
        try:
            import lief as _lief

            lief = _lief
        except ImportError:
            print("WARNING: lief dependency is unavailable", file=sys.stderr)

    if lief and (binary := lief.MachO.parse(inp)):
        macho = binary.at(0)
        print(f"{inp}:")
        print(macho.header)

    if not macho:
        print("falling back to dumb pattern search")

    patch_off, old = scan_for_patch(inp, macho)

    # Check if already patched (exit early)
    if is_b(old):
        print("file is already patched")
        sys.exit(0)

    # Check if output exists
    if os.path.exists(out) and not args.force:
        sys.exit(f"output file '{out}' already exists (use -f to overwrite)")

    new = b_cond_to_b(old)
    vaddr = off_to_vaddr(macho, patch_off) if macho else None

    shutil.copy(inp, out)

    with open(out, "r+b") as f:
        f.seek(patch_off)
        f.write(struct.pack("<I", new))

    print(f"patch: 0x{vaddr:x} [0x{patch_off:x}]" if vaddr else f"patch: [0x{patch_off:x}]")
    print(f"  {old:08x} -> {new:08x}")
    print(f"wrote: {out}")


if __name__ == "__main__":
    main()
