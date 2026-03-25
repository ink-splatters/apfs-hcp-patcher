from __future__ import annotations

from apfs_hcp_patcher.patch import b_cond_to_b, find_pattern_hits
from macho.image import MachOContext


def test_b_cond_to_b_converts_expected_instruction() -> None:
    assert b_cond_to_b(0x54FFFD81) == 0x17FFFFEC


def test_find_pattern_hits_finds_single_candidate() -> None:
    payload = b"\x00" * 4 + b"\x88\x0a\x40\xb9\x1f\x0d\x00\x71\x81\xfd\xff\x54" + b"\x00" * 4
    assert find_pattern_hits(payload, 0, len(payload)) == [12]


def test_function_range_uses_next_symbol_as_upper_bound() -> None:
    context = MachOContext(
        symbol_values=[0x1000, 0x1080],
        symbol_by_name={"_target": 0x1000, "_next": 0x1080},
        virtual_segments=[(0x1000, 0x2000, 0)],
        file_segments=[(0, 0x1000, 0x1000)],
    )
    assert context.function_range("_target") == (0x1000, 0x80)


def test_merged_file_ranges_merges_adjacent_segments() -> None:
    context = MachOContext(
        symbol_values=[],
        symbol_by_name={},
        virtual_segments=[],
        file_segments=[(0x100, 0x180, 0), (0x180, 0x200, 0), (0x240, 0x280, 0)],
    )
    assert context.merged_file_ranges() == [(0x100, 0x200), (0x240, 0x280)]
