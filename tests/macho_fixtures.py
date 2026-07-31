"""Builders for small, structurally valid Mach-O test images."""

from __future__ import annotations

import struct
from dataclasses import dataclass

MACH_HEADER_64 = struct.Struct("<IiiIIIII")
LOAD_COMMAND = struct.Struct("<II")
SEGMENT_COMMAND_64 = struct.Struct("<II16sQQQQiiII")
SYMTAB_COMMAND = struct.Struct("<IIIIII")
FILESET_ENTRY_COMMAND = struct.Struct("<IIQQII")
NLIST_64 = struct.Struct("<IbbHQ")
FAT_HEADER = struct.Struct(">II")
FAT_ARCH = struct.Struct(">IIIII")
FAT_ARCH_64 = struct.Struct(">IIQQII")
U32 = struct.Struct("<I")

MH_MAGIC_64 = 0xFEEDFACF
MH_KEXT_BUNDLE = 0xB
MH_FILESET = 0xC
LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64_ALL = 0
CPU_SUBTYPE_ARM64E = 2

APFS_FILESET_ENTRY = "com.apple.filesystems.apfs"
TARGET_SYMBOL = "_delta_restore_verify_compatibility"
PATCH_PATTERN = bytes.fromhex("880a40b91f0d0071")
B_NE_INSTRUCTION = 0x54FFFD81
B_INSTRUCTION = 0x17FFFFEC

IMAGE_SIZE = 0x800
IMAGE_VMADDR = 0xFFFFFE0008000000
TARGET_SYMBOL_OFFSET = 0x180
NEXT_SYMBOL_OFFSET = TARGET_SYMBOL_OFFSET + 0x100
DECOY_BRANCH_OFFSET = 0x348
SYMTAB_OFFSET = 0x500


@dataclass(frozen=True, slots=True)
class MachOFixture:
    """A Mach-O image and the offsets relevant to patch assertions."""

    data: bytes
    patch_offset: int | None
    decoy_branch_offsets: tuple[int, ...] = ()


def build_thin_macho(
    *,
    include_target_symbol: bool = True,
    target_instructions: tuple[int, ...] = (B_NE_INSTRUCTION,),
    include_decoy: bool = True,
) -> MachOFixture:
    """Build a thin arm64e Mach-O with a symbol table and executable bytes."""
    symbols = (
        [
            (TARGET_SYMBOL, IMAGE_VMADDR + TARGET_SYMBOL_OFFSET),
            ("_next_function", IMAGE_VMADDR + NEXT_SYMBOL_OFFSET),
        ]
        if include_target_symbol
        else [("_other_function", IMAGE_VMADDR + NEXT_SYMBOL_OFFSET)]
    )
    string_table = bytearray(b"\x00")
    symbol_records = bytearray()
    for name, value in symbols:
        name_offset = len(string_table)
        string_table.extend(name.encode())
        string_table.append(0)
        symbol_records.extend(NLIST_64.pack(name_offset, 0x0E, 1, 0, value))

    string_table_offset = SYMTAB_OFFSET + len(symbol_records)
    segment_command = SEGMENT_COMMAND_64.pack(
        LC_SEGMENT_64,
        SEGMENT_COMMAND_64.size,
        b"__TEXT".ljust(16, b"\x00"),
        IMAGE_VMADDR,
        IMAGE_SIZE,
        0,
        IMAGE_SIZE,
        7,
        5,
        0,
        0,
    )
    symtab_command = SYMTAB_COMMAND.pack(
        LC_SYMTAB,
        SYMTAB_COMMAND.size,
        SYMTAB_OFFSET,
        len(symbols),
        string_table_offset,
        len(string_table),
    )
    commands = segment_command + symtab_command
    header = MACH_HEADER_64.pack(
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        CPU_SUBTYPE_ARM64E,
        MH_KEXT_BUNDLE,
        2,
        len(commands),
        0,
        0,
    )

    image = bytearray(IMAGE_SIZE)
    image[: len(header)] = header
    image[len(header) : len(header) + len(commands)] = commands
    image[SYMTAB_OFFSET : SYMTAB_OFFSET + len(symbol_records)] = symbol_records
    image[string_table_offset : string_table_offset + len(string_table)] = string_table

    target_branch_offsets: list[int] = []
    for index, instruction in enumerate(target_instructions):
        pattern_offset = TARGET_SYMBOL_OFFSET + 0x10 + index * 0x20
        branch_offset = pattern_offset + len(PATCH_PATTERN)
        image[pattern_offset:branch_offset] = PATCH_PATTERN
        U32.pack_into(image, branch_offset, instruction)
        target_branch_offsets.append(branch_offset)

    decoy_offsets: tuple[int, ...] = ()
    if include_decoy:
        decoy_pattern_offset = DECOY_BRANCH_OFFSET - len(PATCH_PATTERN)
        image[decoy_pattern_offset:DECOY_BRANCH_OFFSET] = PATCH_PATTERN
        U32.pack_into(image, DECOY_BRANCH_OFFSET, B_NE_INSTRUCTION)
        decoy_offsets = (DECOY_BRANCH_OFFSET,)

    expected_offset = target_branch_offsets[0] if len(target_branch_offsets) == 1 else None
    return MachOFixture(bytes(image), expected_offset, decoy_offsets)


def build_fat_macho(*, fat64: bool, include_arm64e: bool = True) -> MachOFixture:
    """Build a universal Mach-O with an arm64 slice and a preferred second slice."""
    arm64 = build_thin_macho()
    second_slice = build_thin_macho()
    first_offset = 0x1000
    second_offset = 0x2000
    second_cpu = CPU_TYPE_ARM64 if include_arm64e else CPU_TYPE_X86_64
    second_subtype = CPU_SUBTYPE_ARM64E if include_arm64e else 3

    if fat64:
        magic = FAT_MAGIC_64
        architecture_table = b"".join(
            (
                FAT_ARCH_64.pack(
                    CPU_TYPE_ARM64,
                    CPU_SUBTYPE_ARM64_ALL,
                    first_offset,
                    len(arm64.data),
                    12,
                    0,
                ),
                FAT_ARCH_64.pack(
                    second_cpu,
                    second_subtype,
                    second_offset,
                    len(second_slice.data),
                    12,
                    0,
                ),
            )
        )
    else:
        magic = FAT_MAGIC
        architecture_table = b"".join(
            (
                FAT_ARCH.pack(
                    CPU_TYPE_ARM64,
                    CPU_SUBTYPE_ARM64_ALL,
                    first_offset,
                    len(arm64.data),
                    12,
                ),
                FAT_ARCH.pack(
                    second_cpu,
                    second_subtype,
                    second_offset,
                    len(second_slice.data),
                    12,
                ),
            )
        )

    fat = bytearray(second_offset + len(second_slice.data))
    header = FAT_HEADER.pack(magic, 2)
    fat[: len(header)] = header
    fat[len(header) : len(header) + len(architecture_table)] = architecture_table
    fat[first_offset : first_offset + len(arm64.data)] = arm64.data
    fat[second_offset : second_offset + len(second_slice.data)] = second_slice.data

    arm64_patch_offset = arm64.patch_offset
    second_patch_offset = second_slice.patch_offset
    assert arm64_patch_offset is not None
    assert second_patch_offset is not None
    selected_base = second_offset if include_arm64e else first_offset
    selected_patch_offset = second_patch_offset if include_arm64e else arm64_patch_offset
    patch_offset = selected_base + selected_patch_offset
    candidate_offsets = (
        first_offset + arm64_patch_offset,
        second_offset + second_patch_offset,
        *(first_offset + offset for offset in arm64.decoy_branch_offsets),
        *(second_offset + offset for offset in second_slice.decoy_branch_offsets),
    )
    return MachOFixture(
        bytes(fat),
        patch_offset,
        tuple(offset for offset in candidate_offsets if offset != patch_offset),
    )


def build_fileset_macho() -> MachOFixture:
    """Build an MH_FILESET containing a decoy kext and the target APFS kext."""
    decoy = build_thin_macho()
    apfs = build_thin_macho()
    decoy_offset = 0x1000
    apfs_offset = 0x2000
    entries = (
        _fileset_entry_command("com.apple.driver.decoy", decoy_offset),
        _fileset_entry_command(APFS_FILESET_ENTRY, apfs_offset),
    )
    commands = b"".join(entries)
    header = MACH_HEADER_64.pack(
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        CPU_SUBTYPE_ARM64E,
        MH_FILESET,
        len(entries),
        len(commands),
        0,
        0,
    )

    fileset = bytearray(apfs_offset + len(apfs.data))
    fileset[: len(header)] = header
    fileset[len(header) : len(header) + len(commands)] = commands
    fileset[decoy_offset : decoy_offset + len(decoy.data)] = decoy.data
    fileset[apfs_offset : apfs_offset + len(apfs.data)] = apfs.data

    assert decoy.patch_offset is not None
    assert apfs.patch_offset is not None
    return MachOFixture(
        bytes(fileset),
        apfs_offset + apfs.patch_offset,
        (
            decoy_offset + decoy.patch_offset,
            *(decoy_offset + offset for offset in decoy.decoy_branch_offsets),
            *(apfs_offset + offset for offset in apfs.decoy_branch_offsets),
        ),
    )


def build_malformed_load_command_macho() -> bytes:
    """Build a Mach-O whose segment command is smaller than its fixed header."""
    command = LOAD_COMMAND.pack(LC_SEGMENT_64, LOAD_COMMAND.size)
    header = MACH_HEADER_64.pack(
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        CPU_SUBTYPE_ARM64E,
        MH_KEXT_BUNDLE,
        1,
        len(command),
        0,
        0,
    )
    return header + command


def _fileset_entry_command(identifier: str, file_offset: int) -> bytes:
    encoded_identifier = identifier.encode() + b"\x00"
    command_size = _align(FILESET_ENTRY_COMMAND.size + len(encoded_identifier), 8)
    command = FILESET_ENTRY_COMMAND.pack(
        LC_FILESET_ENTRY,
        command_size,
        0,
        file_offset,
        FILESET_ENTRY_COMMAND.size,
        0,
    )
    return (command + encoded_identifier).ljust(command_size, b"\x00")


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment
