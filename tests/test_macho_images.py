from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apfs_hcp_patcher.patch import APFS_FILESET_ENTRY, PatchError, patch_file
from tests.macho_fixtures import (
    B_INSTRUCTION,
    B_NE_INSTRUCTION,
    MachOFixture,
    build_fat_macho,
    build_fileset_macho,
    build_malformed_load_command_macho,
    build_thin_macho,
)

if TYPE_CHECKING:
    from pathlib import Path

    from apfs_hcp_patcher.patch import PatchResult


def test_patches_only_symbol_scoped_candidate_in_thin_macho(tmp_path: Path) -> None:
    fixture = build_thin_macho()

    result, output = _apply_fixture(tmp_path, fixture, "apfs")

    assert result.location.fileset_entry is None
    _assert_only_expected_instruction_changed(fixture, output)


@pytest.mark.parametrize("fat64", [False, True], ids=["fat", "fat64"])
def test_fat_macho_prefers_arm64e_slice(tmp_path: Path, *, fat64: bool) -> None:
    fixture = build_fat_macho(fat64=fat64)

    _, output = _apply_fixture(tmp_path, fixture, f"apfs-{'fat64' if fat64 else 'fat'}")

    _assert_only_expected_instruction_changed(fixture, output)


def test_fat_macho_falls_back_to_arm64_slice(tmp_path: Path) -> None:
    fixture = build_fat_macho(fat64=False, include_arm64e=False)

    _, output = _apply_fixture(tmp_path, fixture, "apfs-arm64")

    _assert_only_expected_instruction_changed(fixture, output)


def test_fileset_selects_apfs_entry_and_ignores_decoys(tmp_path: Path) -> None:
    fixture = build_fileset_macho()

    result, output = _apply_fixture(tmp_path, fixture, "kernelcache")

    assert result.location.fileset_entry == APFS_FILESET_ENTRY
    _assert_only_expected_instruction_changed(fixture, output)


def test_malformed_load_command_is_rejected_without_output(tmp_path: Path) -> None:
    source = tmp_path / "malformed"
    output = tmp_path / "malformed.patched"
    source.write_bytes(build_malformed_load_command_macho())

    with pytest.raises(PatchError, match="LC_SEGMENT_64 command is too small"):
        patch_file(source, output)

    assert not output.exists()


def test_missing_target_symbol_is_rejected_without_fallback(tmp_path: Path) -> None:
    fixture = build_thin_macho(include_target_symbol=False)
    source = tmp_path / "missing-symbol"
    output = tmp_path / "missing-symbol.patched"
    source.write_bytes(fixture.data)

    with pytest.raises(PatchError, match="required symbol not found"):
        patch_file(source, output)

    assert not output.exists()


def test_multiple_symbol_scoped_matches_are_rejected(tmp_path: Path) -> None:
    fixture = build_thin_macho(
        target_instructions=(B_NE_INSTRUCTION, B_NE_INSTRUCTION),
    )
    source = tmp_path / "multiple-matches"
    output = tmp_path / "multiple-matches.patched"
    source.write_bytes(fixture.data)

    with pytest.raises(PatchError, match=r"expected exactly one patch site.*found 2"):
        patch_file(source, output)

    assert not output.exists()


def test_already_patched_input_is_reported_without_output(tmp_path: Path) -> None:
    fixture = build_thin_macho(target_instructions=(B_INSTRUCTION,))
    source = tmp_path / "already-patched"
    output = tmp_path / "already-patched.copy"
    source.write_bytes(fixture.data)

    result = patch_file(source, output)

    assert result.already_patched
    assert result.location.original_instruction == B_INSTRUCTION
    assert not output.exists()


def _apply_fixture(
    tmp_path: Path,
    fixture: MachOFixture,
    name: str,
) -> tuple[PatchResult, Path]:
    source = tmp_path / name
    output = tmp_path / f"{name}.patched"
    source.write_bytes(fixture.data)
    result = patch_file(source, output)
    assert result.location.patch_offset == fixture.patch_offset
    assert not result.already_patched
    return result, output


def _assert_only_expected_instruction_changed(
    fixture: MachOFixture,
    output: Path,
) -> None:
    assert fixture.patch_offset is not None
    expected = bytearray(fixture.data)
    expected[fixture.patch_offset : fixture.patch_offset + 4] = B_INSTRUCTION.to_bytes(4, "little")
    assert output.read_bytes() == expected
    for decoy_offset in fixture.decoy_branch_offsets:
        assert (
            int.from_bytes(expected[decoy_offset : decoy_offset + 4], "little") == B_NE_INSTRUCTION
        )
