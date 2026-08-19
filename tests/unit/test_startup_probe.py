"""The probe runner: fail-fast, network-free, and reporting its own delta.

ADR-002 §6 makes the runner take its checks as DATA and return a `ProbeReport`
rather than `None` - a Mandate-12 requirement rather than ergonomics. Two of the
supplied checks repair and one sweeps, so the probe has a declared mutation
delta, and a `None`-returning procedure gives its caller no way to assert it.

⚠ THE OPEN VOCABULARY IS TESTED HERE TOO. `ProbeCheck` carries only the members
every consumer has; a consumer extends with its own `StrEnum` and the runner must
carry it through untouched. That is what stops the next four servers inheriting
the first one's refusals.
"""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path

import pytest

from mcp_packaging.events import EventName, recorded_events, reset_recorded_events
from mcp_packaging.startup_probe import (
    ProbeCheck,
    ProbeCheckResult,
    StartupRefused,
    check_name,
    private_directory_check,
    private_files_check,
    run,
    shared_secret_check,
    write_path_check,
)


class ConsumerCheck(StrEnum):
    """A consumer's own vocabulary, which this layer must never need to know."""

    DOCUMENT_UNREADABLE = "document_unreadable"


@pytest.fixture(autouse=True)
def _clean_record() -> None:
    reset_recorded_events()


@pytest.fixture
def store(tmp_path: Path) -> Path:
    directory = tmp_path / "store"
    directory.mkdir(mode=0o700)
    return directory


def _passing(check: ProbeCheck) -> object:
    return lambda: ProbeCheckResult(check)


@pytest.mark.contract_shape_unbounded_preservation
def test_a_clean_run_reports_every_check_in_order_and_repairs_nothing(store: Path) -> None:
    report = run(checks=[private_directory_check(store), private_files_check(store)])
    assert report.ran() == (ProbeCheck.STORE_SHARED, ProbeCheck.STORE_FILE_SHARED)
    assert report.repaired() == ()
    assert report.swept == ()


@pytest.mark.error
def test_the_probe_is_fail_fast_so_a_machine_with_three_faults_reports_one(store: Path) -> None:
    """Deliberate. Three refusals in a journal is three things to go and read, and
    the second and third are usually consequences of the first."""
    ran: list[str] = []

    def first() -> ProbeCheckResult:
        ran.append("first")
        raise StartupRefused(ProbeCheck.STORE_ABSENT, str(store))

    def second() -> ProbeCheckResult:
        ran.append("second")
        raise StartupRefused(ProbeCheck.TOKEN_ABSENT)

    with pytest.raises(StartupRefused) as refusal:
        run(checks=[first, second])

    assert ran == ["first"]
    assert refusal.value.check is ProbeCheck.STORE_ABSENT


@pytest.mark.error
def test_a_refusal_carries_the_report_of_everything_that_ran_before_it(store: Path) -> None:
    """⚠ A REPAIR MADE ON THE WAY TO A REFUSAL MUST NOT BE LOST. A probe that
    made the store private and then refused would otherwise have no way to tell
    its caller what it changed - and "the check corrected the permissions and
    refused anyway" is exactly the shape of a store that was readable by every
    account."""
    os.chmod(store, 0o755)

    with pytest.raises(StartupRefused) as refusal:
        run(checks=[private_directory_check(store)])

    report = refusal.value.report
    assert report is not None
    assert report.ran() == (ProbeCheck.STORE_SHARED,)
    assert report.repaired() == (ProbeCheck.STORE_SHARED,)
    assert refusal.value.repaired is True


@pytest.mark.error
def test_a_shared_store_is_repaired_and_still_refused(store: Path) -> None:
    """Both, and neither alone. The repair is so the next start is safe without
    anybody typing a chmod; the refusal is because a store that was readable by
    every account has ALREADY been readable."""
    os.chmod(store, 0o755)
    with pytest.raises(StartupRefused):
        run(checks=[private_directory_check(store)])
    assert oct(os.stat(store).st_mode)[-3:] == "700"


@pytest.mark.error
def test_a_symlink_where_a_directory_was_expected_is_refused(tmp_path: Path) -> None:
    """⚠ CHECKED BEFORE `is_dir`. A symlink to a real directory answers `is_dir`
    truthfully, so a check that asked only that question would pass a store whose
    permission bits belong somewhere else entirely."""
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)

    with pytest.raises(StartupRefused) as refusal:
        run(checks=[private_directory_check(link)])
    assert refusal.value.check is ProbeCheck.STORE_NOT_A_DIRECTORY


@pytest.mark.error
def test_an_absent_store_is_refused_by_its_own_name(tmp_path: Path) -> None:
    with pytest.raises(StartupRefused) as refusal:
        run(checks=[private_directory_check(tmp_path / "never-created")])
    assert refusal.value.check is ProbeCheck.STORE_ABSENT


@pytest.mark.real_io
def test_the_write_check_goes_through_the_real_write_and_leaves_nothing(store: Path) -> None:
    """A sentinel written any other way tests an imitation of the mechanism."""
    written: list[tuple[Path, str]] = []

    def write(directory: Path, name: str, payload: bytes) -> None:
        written.append((directory, name))
        (directory / name).write_bytes(payload)

    report = run(checks=[write_path_check(store, write)])
    assert written and written[0][0] == store
    assert list(store.iterdir()) == []
    assert report.ran() == (ProbeCheck.STORE_WRITE_PATH_BROKEN,)


@pytest.mark.error
def test_a_store_that_will_not_take_a_write_refuses_naming_the_errno_and_the_store(store: Path) -> None:
    """Two fields, not one. The errno NAME is what an operator needs - EROFS and
    ENOSPC are different repairs - and on a box running two of these services the
    only question worth asking first is WHICH store."""

    def write(directory: Path, name: str, payload: bytes) -> None:
        raise OSError(30, "Read-only file system")

    with pytest.raises(StartupRefused) as refusal:
        run(checks=[write_path_check(store, write)])

    assert refusal.value.check is ProbeCheck.STORE_WRITE_PATH_BROKEN
    assert refusal.value.detail == "EROFS"
    assert refusal.value.store == str(store)


@pytest.mark.error
def test_a_medium_that_will_not_promise_durability_is_a_different_refusal(store: Path) -> None:
    """A failure to FLUSH is not a full disk. On such a medium a rename cannot be
    promised to survive a power cut, which is the substrate lie that ends grants."""

    def write(directory: Path, name: str, payload: bytes) -> None:
        raise OSError(22, "Invalid argument")

    with pytest.raises(StartupRefused) as refusal:
        run(checks=[write_path_check(store, write)])
    assert refusal.value.check is ProbeCheck.STORE_DURABILITY_UNAVAILABLE


@pytest.mark.real_io
def test_the_sweep_is_reported_as_part_of_the_declared_delta(store: Path) -> None:
    """The sweep IS part of the check's delta, so it comes back in the report. A
    runner that had to be told about it separately could not stay generic."""

    def write(directory: Path, name: str, payload: bytes) -> None:
        (directory / name).write_bytes(payload)

    report = run(checks=[write_path_check(store, write, sweep=lambda _: ("stale.tmp",))])
    assert report.swept == ("stale.tmp",)
    assert report.repaired() == (ProbeCheck.STORE_WRITE_PATH_BROKEN,)


@pytest.mark.error
@pytest.mark.parametrize(
    ("secret", "expected"),
    [(None, ProbeCheck.TOKEN_ABSENT), ("", ProbeCheck.TOKEN_ABSENT), ("short", ProbeCheck.TOKEN_TOO_SHORT)],
)
def test_absence_and_shortness_are_named_separately(secret: str | None, expected: ProbeCheck) -> None:
    """Two different things for an operator to go and fix."""
    with pytest.raises(StartupRefused) as refusal:
        run(checks=[shared_secret_check(secret, 32)])
    assert refusal.value.check is expected


@pytest.mark.error
def test_a_refusal_emits_one_structured_event_naming_the_check(store: Path) -> None:
    def write(directory: Path, name: str, payload: bytes) -> None:
        raise OSError(30, "Read-only file system")

    with pytest.raises(StartupRefused):
        run(checks=[write_path_check(store, write)])

    events = recorded_events(EventName.STARTUP_REFUSED)
    assert len(events) == 1
    assert events[0]["check"] == "store_write_path_broken"
    assert events[0]["detail"] == "EROFS"
    assert events[0]["store"] == str(store)


@pytest.mark.boundary
def test_a_consumer_may_refuse_with_its_own_vocabulary() -> None:
    """⚠ THE WHOLE REASON `ProbeCheck` IS OPEN. The reference enum carried
    `store_corrupt` and `seed_rolled_back` - one consumer's document schema and
    another's rotation semantics. A closed enum would make this layer learn a
    domain word so that its own consumer could refuse."""

    def consumer_check() -> ProbeCheckResult:
        raise StartupRefused(ConsumerCheck.DOCUMENT_UNREADABLE, "detail")

    with pytest.raises(StartupRefused) as refusal:
        run(checks=[consumer_check])

    assert refusal.value.check is ConsumerCheck.DOCUMENT_UNREADABLE
    assert check_name(refusal.value.check) == "document_unreadable"
    assert recorded_events(EventName.STARTUP_REFUSED)[0]["check"] == "document_unreadable"


@pytest.mark.property
def test_check_name_renders_both_vocabularies_and_a_bare_string() -> None:
    assert check_name(ProbeCheck.STORE_ABSENT) == "store_absent"
    assert check_name(ConsumerCheck.DOCUMENT_UNREADABLE) == "document_unreadable"
    assert check_name("hand_written") == "hand_written"
