"""Mode enforcement over a store directory. Real filesystem, read back off it.

ADR-002 §7 classes `enforce_store_modes` as a BOUNDED-CHANGE shape whose declared
mutation set is "the mode bits of the store directory and every file directly in
it", and requires the mode to be read BACK OFF THE FILESYSTEM rather than
inferred from a `chmod` that returned zero. So every assertion here stats the
real thing; a fake filesystem would be testing the fake.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from mcp_packaging.store_modes import (
    STORE_DIRECTORY_MODE,
    STORE_FILE_MODE,
    ModeEnforcement,
    enforce_directory_mode,
    enforce_file_modes,
    enforce_store_modes,
    is_shared,
    mode_of,
    shared_files,
    store_lock,
)


@pytest.fixture
def store(tmp_path: Path) -> Path:
    """A private store directory, as a healthy host would have."""
    directory = tmp_path / "store"
    directory.mkdir(mode=STORE_DIRECTORY_MODE)
    return directory


@pytest.mark.real_io
def test_a_private_store_is_left_alone(store: Path) -> None:
    """Nothing repaired means nothing changed. The report is how a caller knows."""
    report = enforce_store_modes(store)
    assert report == ModeEnforcement()
    assert not report.repaired_anything()


@pytest.mark.real_io
def test_a_shared_directory_is_repaired_and_the_repair_is_reported(store: Path) -> None:
    os.chmod(store, 0o755)
    report = enforce_store_modes(store)
    assert report.directory_repaired
    assert mode_of(store) == STORE_DIRECTORY_MODE


@pytest.mark.real_io
def test_a_shared_file_is_repaired_and_named(store: Path) -> None:
    """The report names WHICH files were granting something. An operator fixing a
    host needs the names; a boolean would tell them only that something was."""
    # ⚠ THE PRIVATE ONE IS MADE PRIVATE EXPLICITLY. `write_text` creates at the
    # ambient umask, which on an ordinary host is 0644 - so a test that skipped
    # this line would find BOTH files repaired and could never tell a check that
    # repairs the right file from one that repairs everything it can see.
    (store / "one").write_text("x")
    os.chmod(store / "one", STORE_FILE_MODE)
    (store / "two").write_text("y")
    os.chmod(store / "two", 0o644)

    report = enforce_store_modes(store)
    assert report.files_repaired == ("two",)
    assert mode_of(store / "two") == STORE_FILE_MODE


@pytest.mark.real_io
def test_the_check_iterates_and_never_names_a_document(store: Path) -> None:
    """⚠ THE GUARANTEE MUST NOT STOP GUARANTEEING ANYTHING THE DAY THE LAYOUT
    GAINS A FILE. A check that named the document it expected would pass over a
    world-readable lock, a sentinel, or whatever the store gains next."""
    for name in (".store.lock", ".sentinel", "document.json", "surprise"):
        path = store / name
        path.write_text("x")
        os.chmod(path, 0o666)

    assert set(shared_files(store)) == {".store.lock", ".sentinel", "document.json", "surprise"}
    assert set(enforce_file_modes(store)) == {".store.lock", ".sentinel", "document.json", "surprise"}
    assert shared_files(store) == ()


@pytest.mark.real_io
def test_a_directory_is_not_mistaken_for_a_file(store: Path) -> None:
    """`_files_in` takes files directly in the store. A subdirectory is neither
    repaired nor reported, because its own contents are a different question."""
    (store / "inner").mkdir(mode=0o777)
    assert shared_files(store) == ()


@pytest.mark.real_io
def test_a_symlink_is_not_followed(store: Path) -> None:
    """A link's target belongs to somewhere else, and chmod-ing through one would
    change permission bits outside the declared mutation set."""
    outside = store.parent / "outside"
    outside.write_text("x")
    os.chmod(outside, 0o666)
    (store / "link").symlink_to(outside)

    assert shared_files(store) == ()
    assert mode_of(outside) == 0o666


@pytest.mark.real_io
def test_the_lock_file_is_created_private_by_the_creating_syscall(store: Path) -> None:
    """⚠ CREATED AT 0600, NOT CHMOD-ED TO IT. Between an `open` and a `chmod`
    there is an instant in which the file is readable by everyone, and the
    service's own privacy check can see it. Mode-from-the-creating-syscall has no
    such instant."""
    with store_lock(store):
        assert mode_of(store / ".store.lock") == STORE_FILE_MODE
    assert not is_shared(store / ".store.lock")


@pytest.mark.real_io
def test_the_lock_is_released_when_the_block_ends(store: Path) -> None:
    """Taken twice in sequence, which an unreleased advisory lock would hang on."""
    with store_lock(store):
        pass
    with store_lock(store):
        pass


@pytest.mark.real_io
def test_a_mode_is_read_back_and_never_inferred_from_a_successful_chmod(store: Path) -> None:
    """The mode is asserted off `os.stat`, which is the substrate's answer rather
    than the call's. `ModeNotHonoured` exists for the filesystem that accepts the
    change and does not apply it; it cannot be provoked on a healthy tmpfs, so
    what is asserted here is that the read-back happens at all."""
    (store / "doc").write_text("x")
    os.chmod(store / "doc", 0o604)
    enforce_directory_mode(store)
    enforce_file_modes(store)
    observed = stat.S_IMODE(os.stat(store / "doc").st_mode)
    assert observed == STORE_FILE_MODE
