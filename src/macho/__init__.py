"""Small, reusable Mach-O helpers."""

from .image import (
    FileRange,
    MachOContext,
    MachOError,
    SegmentEntry,
    ThinMachO,
    find_fileset_entry,
    is_fileset_image,
    load_fileset_macho,
    load_standalone_macho,
    read_c_string,
)
from .ops import ad_hoc_codesign, copy_and_write_u32, is_universal, read_u32, thin_arm64e

__all__ = [
    "FileRange",
    "MachOContext",
    "MachOError",
    "SegmentEntry",
    "ThinMachO",
    "ad_hoc_codesign",
    "copy_and_write_u32",
    "find_fileset_entry",
    "is_fileset_image",
    "is_universal",
    "load_fileset_macho",
    "load_standalone_macho",
    "read_c_string",
    "read_u32",
    "thin_arm64e",
]
