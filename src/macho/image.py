"""Mach-O image parsing and address mapping."""

from __future__ import annotations

import mmap
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

from ._spec import (
    CPU_SUBTYPE_ARM64E,
    CPU_TYPE_ARM64,
    FAT_ARCH_64_STRUCT,
    FAT_HEADER_STRUCT,
    FAT_MAGIC_64,
    FILESET_ENTRY_COMMAND_STRUCT,
    LC_FILESET_ENTRY,
    LC_SEGMENT_64,
    LC_SYMTAB,
    LOAD_COMMAND_STRUCT,
    MACH_HEADER_64_STRUCT,
    MACH_HEADER_SIZE,
    MH_FILESET,
    MH_MAGIC_64,
    NLIST_64_STRUCT,
    SEGMENT_COMMAND_64_STRUCT,
    SYMTAB_COMMAND_STRUCT,
)

type SegmentEntry = tuple[int, int, int]  # (start, end, base)
type FileRange = tuple[int, int]
type ByteBuffer = bytes | bytearray | mmap.mmap

DEFAULT_FUNC_SCAN_SIZE = 0x200
MAX_FUNC_SCAN_SIZE = 0x400


class MachOError(ValueError):
    """Raised when Mach-O parsing fails."""


@dataclass(slots=True)
class MachOContext:
    """Fast lookup tables derived from a Mach-O image."""

    symbol_values: list[int]
    symbol_by_name: dict[str, int]
    virtual_segments: list[SegmentEntry]
    file_segments: list[SegmentEntry]

    def function_range(self, name: str) -> tuple[int, int] | None:
        """Return the symbol address and a bounded scan size."""
        addr = self.symbol_by_name.get(name)
        if addr is None:
            return None

        next_index = bisect_right(self.symbol_values, addr)
        next_addr = (
            self.symbol_values[next_index]
            if next_index < len(self.symbol_values)
            else addr + DEFAULT_FUNC_SCAN_SIZE
        )
        return addr, min(next_addr - addr, MAX_FUNC_SCAN_SIZE)

    def merged_file_ranges(self) -> list[FileRange]:
        """Return merged file ranges covered by mapped segments."""
        ranges = sorted((start, end) for start, end, _ in self.file_segments)
        merged: list[list[int]] = []
        for start, end in ranges:
            if not merged or start > merged[-1][1]:
                merged.append([start, end])
                continue
            if end > merged[-1][1]:
                merged[-1][1] = end
        return [(start, end) for start, end in merged]

    def vaddr_to_off(self, vaddr: int) -> int | None:
        """Convert a virtual address to a file offset."""
        for start, end, file_offset in self.virtual_segments:
            if start <= vaddr < end:
                return vaddr - start + file_offset
        return None

    def off_to_vaddr(self, offset: int) -> int | None:
        """Convert a file offset to a virtual address."""
        for start, end, virtual_address in self.file_segments:
            if start <= offset < end:
                return offset - start + virtual_address
        return None


@dataclass(slots=True)
class ThinMachO:
    """Thin Mach-O layout information for address/offset mapping."""

    path: Path
    filetype: int
    segments: list[SegmentEntry]

    @classmethod
    def from_path(cls, path: str | Path) -> ThinMachO:
        raw = Path(path).read_bytes()
        filetype, segments = _parse_image_layout(raw, 0)
        return cls(path=Path(path), filetype=filetype, segments=segments)

    def is_fileset(self) -> bool:
        return self.filetype == MH_FILESET

    def vaddr_to_off(self, vaddr: int) -> int | None:
        """Convert a virtual address to a file offset."""
        for start, end, fileoff in self.segments:
            if start <= vaddr < end:
                return vaddr - start + fileoff
        return None


def is_fileset_image(buf: ByteBuffer) -> bool:
    """Return whether a Mach-O buffer is an MH_FILESET image."""
    if len(buf) < MACH_HEADER_SIZE:
        return False
    magic, _, _, filetype, _, _, _, _ = MACH_HEADER_64_STRUCT.unpack_from(buf, 0)
    return magic == MH_MAGIC_64 and filetype == MH_FILESET


def read_c_string(buf: ByteBuffer, start: int, limit: int) -> str:
    """Read a bounded NUL-terminated UTF-8 string."""
    end = buf.find(b"\x00", start, limit)
    if end == -1:
        end = limit
    return bytes(buf[start:end]).decode("utf-8", "replace")


def find_fileset_entry(mm: ByteBuffer, entry_id: str) -> int:
    """Return the container file offset of a fileset entry."""
    _, filetype, ncmds = _read_header(mm, 0)
    if filetype != MH_FILESET:
        raise MachOError("input image is not an MH_FILESET Mach-O")

    for load_offset, cmd, cmdsize in _iter_load_commands(mm, MACH_HEADER_SIZE, ncmds):
        if cmd != LC_FILESET_ENTRY:
            continue
        _, _, _, fileoff, entry_id_offset, _ = FILESET_ENTRY_COMMAND_STRUCT.unpack_from(
            mm, load_offset
        )
        string_offset = load_offset + entry_id_offset
        if load_offset <= string_offset < load_offset + cmdsize:
            identifier = read_c_string(mm, string_offset, load_offset + cmdsize)
            if identifier == entry_id:
                return fileoff

    raise MachOError(f"fileset entry not found: {entry_id}")


def load_fileset_macho(mm: ByteBuffer, entry_id: str) -> MachOContext:
    """Load segment and symbol metadata for a fileset entry."""
    return load_macho_context_from_image(mm, find_fileset_entry(mm, entry_id))


def load_standalone_macho(mm: ByteBuffer) -> MachOContext:
    """Load metadata from a thin or FAT Mach-O."""
    if len(mm) < 4:
        raise MachOError("input file is too small to be a Mach-O")

    magic = int.from_bytes(mm[:4], "big")
    if magic == FAT_MAGIC_64:
        return load_macho_context_from_image(mm, _find_arm64e_slice(mm))

    return load_macho_context_from_image(mm, 0)


def load_macho_context_from_image(mm: ByteBuffer, base_offset: int) -> MachOContext:
    """Load segment and symbol metadata from a thin Mach-O within a buffer."""
    _, _, ncmds = _read_header(mm, base_offset)

    segments: list[SegmentEntry] = []
    symbol_values: list[int] = []
    symbol_by_name: dict[str, int] = {}
    symoff: int | None = None
    nsyms: int | None = None
    stroff: int | None = None
    strsize: int | None = None

    command_offset = base_offset + MACH_HEADER_SIZE
    for load_offset, cmd, _ in _iter_load_commands(mm, command_offset, ncmds):
        if cmd == LC_SEGMENT_64:
            (
                _,
                _,
                _,
                vmaddr,
                vmsize,
                fileoff,
                filesize,
                _,
                _,
                _,
                _,
            ) = SEGMENT_COMMAND_64_STRUCT.unpack_from(mm, load_offset)
            if vmsize > 0 and filesize > 0:
                segments.append((vmaddr, vmaddr + vmsize, fileoff))
        elif cmd == LC_SYMTAB:
            _, _, symoff, nsyms, stroff, strsize = SYMTAB_COMMAND_STRUCT.unpack_from(
                mm, load_offset
            )

    fileoff_bias = (
        base_offset if segments and min(fileoff for _, _, fileoff in segments) < base_offset else 0
    )
    if fileoff_bias:
        segments = [(start, end, fileoff + fileoff_bias) for start, end, fileoff in segments]
        if symoff is not None:
            symoff += fileoff_bias
        if stroff is not None:
            stroff += fileoff_bias

    if symoff is not None and nsyms is not None and stroff is not None and strsize is not None:
        string_end = stroff + strsize
        symbol_end = symoff + nsyms * NLIST_64_STRUCT.size
        if string_end > len(mm) or symbol_end > len(mm):
            raise MachOError("symbol table exceeds input bounds")

        for index in range(nsyms):
            name_index, _, _, _, value = NLIST_64_STRUCT.unpack_from(
                mm,
                symoff + index * NLIST_64_STRUCT.size,
            )
            if value == 0 or name_index == 0 or stroff + name_index >= string_end:
                continue
            name = read_c_string(mm, stroff + name_index, string_end)
            symbol_values.append(value)
            symbol_by_name[name] = value

    return MachOContext(
        symbol_values=sorted(symbol_values),
        symbol_by_name=symbol_by_name,
        virtual_segments=segments,
        file_segments=[
            (fileoff, fileoff + (end - start), start) for start, end, fileoff in segments
        ],
    )


def _find_arm64e_slice(mm: ByteBuffer) -> int:
    if len(mm) < FAT_HEADER_STRUCT.size:
        raise MachOError("input file is too small to be a FAT Mach-O")

    magic, nfat_arch = FAT_HEADER_STRUCT.unpack_from(mm, 0)
    if magic != FAT_MAGIC_64:
        raise MachOError("input file is not a FAT64 Mach-O")

    fallback: int | None = None
    offset = FAT_HEADER_STRUCT.size
    for _ in range(nfat_arch):
        if offset + FAT_ARCH_64_STRUCT.size > len(mm):
            raise MachOError("truncated FAT architecture table")
        cputype, cpusubtype, arch_offset, _, _, _ = FAT_ARCH_64_STRUCT.unpack_from(mm, offset)
        if cputype == CPU_TYPE_ARM64:
            if (cpusubtype & 0x00FFFFFF) == CPU_SUBTYPE_ARM64E:
                return arch_offset
            if fallback is None:
                fallback = arch_offset
        offset += FAT_ARCH_64_STRUCT.size

    if fallback is None:
        raise MachOError("failed to find arm64 or arm64e slice in FAT Mach-O")
    return fallback


def _parse_image_layout(buf: bytes, base_offset: int) -> tuple[int, list[SegmentEntry]]:
    _, filetype, ncmds = _read_header(buf, base_offset)
    segments: list[SegmentEntry] = []

    command_offset = base_offset + MACH_HEADER_SIZE
    for load_offset, cmd, _ in _iter_load_commands(buf, command_offset, ncmds):
        if cmd != LC_SEGMENT_64:
            continue
        (
            _,
            _,
            _,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            _,
            _,
            _,
            _,
        ) = SEGMENT_COMMAND_64_STRUCT.unpack_from(buf, load_offset)
        if vmsize > 0 and filesize > 0:
            segments.append((vmaddr, vmaddr + vmsize, fileoff))

    return filetype, segments


def _read_header(buf: ByteBuffer, base_offset: int) -> tuple[int, int, int]:
    if base_offset < 0 or base_offset + MACH_HEADER_SIZE > len(buf):
        raise MachOError("truncated Mach-O header")
    magic, _, _, filetype, ncmds, _, _, _ = MACH_HEADER_64_STRUCT.unpack_from(buf, base_offset)
    if magic != MH_MAGIC_64:
        raise MachOError("input file is not a thin 64-bit Mach-O")
    return magic, filetype, ncmds


def _iter_load_commands(
    buf: ByteBuffer,
    offset: int,
    ncmds: int,
) -> list[tuple[int, int, int]]:
    commands: list[tuple[int, int, int]] = []
    load_offset = offset
    for _ in range(ncmds):
        if load_offset + LOAD_COMMAND_STRUCT.size > len(buf):
            raise MachOError("truncated Mach-O load command table")
        cmd, cmdsize = LOAD_COMMAND_STRUCT.unpack_from(buf, load_offset)
        if cmdsize < LOAD_COMMAND_STRUCT.size or load_offset + cmdsize > len(buf):
            raise MachOError("invalid Mach-O load command size")
        commands.append((load_offset, cmd, cmdsize))
        load_offset += cmdsize
    return commands
