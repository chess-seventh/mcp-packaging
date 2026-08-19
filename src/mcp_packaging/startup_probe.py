"""The startup probe runner: a list of injected checks, fail-fast, network-free.

ADR-002 §6 inverts the reference implementation's hardcoded probe: the runner
takes its checks as data, so a consumer appends its own without the runner
changing, and ``common/`` never imports a per-server package again.

It returns a ``ProbeReport`` rather than ``None`` (ADR-002 §6). Two checks repair
and one sweeps, so the probe has a declared mutation delta - and a ``None``
returning procedure gives its caller no way to assert that delta.

Two properties are load-bearing and are written here rather than rediscovered:
the probe is **fail-fast** (a machine with three faults reports one), and it
performs **no network I/O of any kind** (ADR-004 §8, enforced by import contract,
not by convention).

A refusal CARRIES the report of everything that ran before it. A probe that
repaired the store and then refused would otherwise have no way to tell its caller
what it repaired, and "the check corrected the permissions and refused anyway" is
exactly the shape of a store that was readable by every account: the world is put
right so the next start is safe, and the operator is still told, because a store
that was shared has already been readable by whoever was there.
"""

from __future__ import annotations

import contextlib
import errno
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from mcp_packaging.events import EventName, emit_event
from mcp_packaging.store_modes import (
    ModeNotHonoured,
    enforce_directory_mode,
    enforce_file_modes,
    shared_files,
)


class ProbeCheck(StrEnum):
    """The catalogued checks EVERY consumer has, by the ``check`` field a refusal carries.

    ⚠ AN OPEN VOCABULARY, and it is open for the same reason
    :class:`~mcp_packaging.events.EventName` is (ADR-002 §1). The reference
    implementation's enum also held ``store_corrupt`` and ``seed_rolled_back`` -
    the first is about a document only the consumer can parse, the second is one
    consumer's rotation semantics. A closed enum here would make this layer learn
    a domain word to let its own consumer refuse, which is the boundary rule
    failing at the one place it is easiest to miss.

    A consumer declares its own ``StrEnum`` of further checks and raises with it;
    every function here takes ``ProbeCheck | str`` and renders it through
    :func:`check_name`.
    """

    STORE_NOT_A_DIRECTORY = "store_not_a_directory"
    STORE_ABSENT = "store_absent"
    STORE_SHARED = "store_shared"
    STORE_FILE_SHARED = "store_file_shared"
    STORE_WRITE_PATH_BROKEN = "store_write_path_broken"
    MODE_NOT_HONOURED = "mode_not_honoured"
    STORE_DURABILITY_UNAVAILABLE = "store_durability_unavailable"
    CREDENTIALS_INCOMPLETE = "credentials_incomplete"
    CREDENTIALS_FILE_ABSENT = "credentials_file_absent"
    TOKEN_ABSENT = "token_absent"
    TOKEN_TOO_SHORT = "token_too_short"


#: A check name, whichever vocabulary it came from: this layer's or a consumer's.
ProbeCheckName = ProbeCheck | str


def check_name(check: ProbeCheckName) -> str:
    """The wire spelling of a check name, whichever enum it arrived from.

    Args:
        check: A member of :class:`ProbeCheck`, or of a consumer's own extension.

    Returns:
        The string a refusal, an event and a machine check all read.
    """
    return check.value if isinstance(check, StrEnum) else str(check)


class StartupRefused(RuntimeError):
    """A probe check refused the start, naming the check and nothing else.

    ``detail`` is a CLOSED VOCABULARY (ADR-004 §5): a check-specific string from a
    fixed set, a filesystem path, or an ``errno`` name. It may **never** carry
    exception text derived from document content - a ``detail=repr(exc)`` on the
    corrupt-document check puts fragments of a live refresh token in the journal.
    """

    def __init__(self, check: ProbeCheckName, detail: str = "", *, repaired: bool = False, store: str = "") -> None:
        """Record which check refused, and a detail from the closed vocabulary.

        Args:
            check: The check that refused.
            detail: A path, an errno name, or a fixed check-specific string.
            repaired: Whether this check changed the world before refusing. A
                store that was readable by every account is made private AND
                refused; the caller must be able to see both.
            store: The store the refusal is about, when it is about one.

                ⚠ A SECOND FIELD RATHER THAN A SECOND MEANING FOR ``detail``, and
                the machine check is what asked for it. The write refusal put the
                errno NAME in ``detail`` - which an operator needs, because EROFS
                and ENOSPC are different repairs - and so the one thing it did not
                say was WHICH store would not take the write. On a box running two
                of these services that is the only question worth asking first.

                Crowding both into ``detail`` would have made a closed vocabulary
                into free text, which is how a field that must never carry document
                content starts carrying it.
        """
        super().__init__(f"startup refused: {check_name(check)}")
        self.check = check
        self.detail = detail
        self.repaired = repaired
        self.store = store
        self.report: ProbeReport | None = None


@dataclass(frozen=True)
class ProbeCheckResult:
    """What one check did.

    Attributes:
        check: The check that ran.
        repaired: Whether it changed the world to make the contract hold.
        swept: Paths this check removed. A third field rather than a second return
            value, because the sweep IS part of the check's declared delta and a
            runner that had to be told about it separately could not stay generic.
    """

    check: ProbeCheckName
    repaired: bool = False
    swept: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProbeReport:
    """The probe's declared delta, as data the caller can assert.

    Attributes:
        results: One result per check that ran, in order.
        swept: Paths of stale temporary files removed at startup.
    """

    results: tuple[ProbeCheckResult, ...] = ()
    swept: tuple[str, ...] = ()

    def ran(self) -> tuple[ProbeCheckName, ...]:
        """The checks that ran, in order."""
        return tuple(result.check for result in self.results)

    def repaired(self) -> tuple[ProbeCheckName, ...]:
        """The checks that changed the world to make the contract hold."""
        return tuple(result.check for result in self.results if result.repaired)


ProbeCheckFn = Callable[[], ProbeCheckResult]


def run(*, checks: Sequence[ProbeCheckFn]) -> ProbeReport:
    """Run every check in order, stopping at the first refusal.

    Args:
        checks: The checks to run, in the order they must run.

    Returns:
        The report naming which checks ran and which repaired.

    Raises:
        StartupRefused: On the first failing check. Fail-fast is deliberate: a
            machine with three faults reports one. The refusal carries the report
            of everything that ran before it, so a repair made on the way to a
            refusal is not lost.
    """
    results: list[ProbeCheckResult] = []
    for check in checks:
        try:
            results.append(check())
        except StartupRefused as refusal:
            results.append(ProbeCheckResult(refusal.check, repaired=refusal.repaired))
            refusal.report = _report(results)
            emit_event(
                EventName.STARTUP_REFUSED,
                check=check_name(refusal.check),
                detail=refusal.detail,
                **({"store": refusal.store} if refusal.store else {}),
            )
            raise
    return _report(results)


def private_directory_check(path: Path) -> ProbeCheckFn:
    """A check that the directory exists, is a real directory, and is private.

    Args:
        path: The store directory.

    Returns:
        The check. It REPAIRS a shared directory before refusing, so the next start
        is safe whether or not the operator reads the refusal first.
    """

    def check() -> ProbeCheckResult:
        _refuse_unless_a_real_directory(path)
        return _private_or_refused(path)

    return check


def private_files_check(path: Path) -> ProbeCheckFn:
    """A check that every file directly in the directory is private.

    ITERATES. It never names a document: naming one means the guarantee silently
    stops guaranteeing anything the day the store gains another file, and it has
    already gained two - a lock and a sentinel.

    Args:
        path: The store directory.

    Returns:
        The check.
    """

    def check() -> ProbeCheckResult:
        if not shared_files(path):
            return ProbeCheckResult(ProbeCheck.STORE_FILE_SHARED)
        enforce_file_modes(path)
        raise StartupRefused(ProbeCheck.STORE_FILE_SHARED, str(path), repaired=True)

    return check


def write_path_check(
    path: Path,
    write: Callable[..., None],
    sweep: Callable[[Path], tuple[str, ...]] | None = None,
) -> ProbeCheckFn:
    """A check that writes a sentinel through the REAL write path and reads it back.

    A sentinel written any other way tests a hand-rolled imitation of the mechanism
    rather than the mechanism. This is the check that would have caught the
    reference implementation's own write, and it only works because it goes through
    the same function a renewal goes through.

    Args:
        path: The store directory.
        write: The durable-write function itself, bound to that directory. Not a
            ``TokenWriter``: the probe must exercise the mechanism and must not be
            able to write the token store (ADR-002 §7, ADR-004 §5).
        sweep: The clear-away for what an interrupted write left behind, injected
            so this layer learns no file naming convention of the consumer's. It
            runs BEFORE the sentinel and belongs to the same check: debris and a
            sentinel are two halves of one question - can this store be written
            through - and a machine that died mid-renewal is not a fault to refuse.

    Returns:
        The check.
    """

    def check() -> ProbeCheckResult:
        swept = () if sweep is None else sweep(path)
        sentinel = path / SENTINEL_FILE_NAME
        try:
            write(path, SENTINEL_FILE_NAME, SENTINEL_PAYLOAD)
            _refuse_unless_read_back(sentinel)
        except OSError as failure:
            raise StartupRefused(_write_refusal(failure), _errno_name(failure), store=str(path)) from None
        finally:
            # ⚠ SUPPRESSED, AND THE MACHINE CHECK IS WHAT FOUND IT. On a store the
            # service cannot write, the write above refuses correctly - and then
            # this line raised `OSError: Read-only file system` on its way out,
            # which REPLACED the named refusal with an unhandled traceback.
            #
            # Three things went with it, and they are the three this whole design
            # is about: the operator got a stack trace instead of the one line
            # naming the check and the store; the `health.startup.refused` event
            # was never emitted, so nothing downstream saw a refusal at all; and
            # the process exited 1 rather than 78, so "a check can tell a refusal
            # from a crash" was false exactly when it mattered.
            #
            # A `finally` that can raise does not clean up after a failure - it
            # overwrites it. Same reasoning as `_discard` in the token store,
            # which suppresses for this reason and says so.
            with contextlib.suppress(OSError):
                sentinel.unlink(missing_ok=True)
        return ProbeCheckResult(ProbeCheck.STORE_WRITE_PATH_BROKEN, repaired=bool(swept), swept=swept)

    return check


def shared_secret_check(token: str | None, minimum_length: int) -> ProbeCheckFn:
    """A check that a shared secret is present and clears the length floor.

    Args:
        token: The secret this server was configured with, or None.
        minimum_length: The floor it must clear.

    Returns:
        The check. Its refusals name absence and shortness separately, because
        the two are different things for an operator to go and fix.
    """

    def check() -> ProbeCheckResult:
        if not token:
            raise StartupRefused(ProbeCheck.TOKEN_ABSENT)
        if len(token) < minimum_length:
            raise StartupRefused(ProbeCheck.TOKEN_TOO_SHORT, f"fewer than {minimum_length} characters")
        return ProbeCheckResult(ProbeCheck.TOKEN_TOO_SHORT)

    return check


#: The file the write-path check publishes and then removes. Its name says what it
#: is, and it does not collide with the working-copy pattern the sweep looks for.
SENTINEL_FILE_NAME = ".sentinel"

#: What the sentinel carries. A fixed, meaningless byte string - never anything
#: derived from a credential, because the sentinel is written into the same
#: directory as the document and could outlive the check on a machine that dies.
SENTINEL_PAYLOAD = b"startup-probe\n"


def _report(results: Sequence[ProbeCheckResult]) -> ProbeReport:
    """One report from the results so far, with the sweep gathered across them."""
    return ProbeReport(
        results=tuple(results),
        swept=tuple(name for result in results for name in result.swept),
    )


def _refuse_unless_a_real_directory(path: Path) -> None:
    """Refuse a link where a directory was expected, and an absent store.

    The link case is checked FIRST. A symlink to a real directory answers ``is_dir``
    truthfully, so a check that asked only that question would pass a store whose
    permission bits belong to somewhere else entirely.
    """
    if path.is_symlink():
        raise StartupRefused(ProbeCheck.STORE_NOT_A_DIRECTORY, str(path))
    if not path.exists():
        raise StartupRefused(ProbeCheck.STORE_ABSENT, str(path))
    if not path.is_dir():
        raise StartupRefused(ProbeCheck.STORE_NOT_A_DIRECTORY, str(path))


def _private_or_refused(path: Path) -> ProbeCheckResult:
    """Make the directory private, and refuse if it was not already.

    Repair AND refuse. The repair is so the next start is safe without anybody
    typing a ``chmod``; the refusal is because a store that was readable by every
    account has ALREADY been readable, and that is the operator's to know rather
    than the service's to paper over.
    """
    try:
        was_shared = enforce_directory_mode(path)
    except ModeNotHonoured as lie:
        raise StartupRefused(ProbeCheck.MODE_NOT_HONOURED, str(lie.path)) from None
    if was_shared:
        raise StartupRefused(ProbeCheck.STORE_SHARED, str(path), repaired=True)
    return ProbeCheckResult(ProbeCheck.STORE_SHARED)


def _refuse_unless_read_back(sentinel: Path) -> None:
    """Refuse a write path that accepted a sentinel it cannot return.

    Read back off the machine. A write that returned success is evidence about the
    call, not about the medium.
    """
    if sentinel.read_bytes() != SENTINEL_PAYLOAD:
        raise StartupRefused(ProbeCheck.STORE_WRITE_PATH_BROKEN, "sentinel did not read back")


def _write_refusal(failure: OSError) -> ProbeCheck:
    """Which refusal an operating-system failure on the write path is.

    A failure to FLUSH is a different fact from a failure to write: the first says
    the medium will not promise durability, which is the substrate lie that ends
    grants, and it must not be reported as a full disk.
    """
    if _errno_name(failure) in DURABILITY_ERRNOS:
        return ProbeCheck.STORE_DURABILITY_UNAVAILABLE
    return ProbeCheck.STORE_WRITE_PATH_BROKEN


def _errno_name(failure: OSError) -> str:
    """The errno's NAME, which is the closed-vocabulary detail a refusal may carry.

    The name and never ``strerror``: a message is locale-dependent prose, and the
    detail field is a vocabulary an operator and a check both read.
    """
    return errno.errorcode.get(failure.errno or 0, "EUNKNOWN")


#: The errno names a filesystem uses to say it will not flush a directory. On such
#: a medium the rename cannot be promised to survive a power cut, which is exactly
#: the lie that costs a grant.
DURABILITY_ERRNOS: frozenset[str] = frozenset({"EINVAL", "ENOSYS", "EOPNOTSUPP", "ENOTSUP"})
