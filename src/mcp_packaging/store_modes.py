"""Advisory locking and mode enforcement over a store directory.

ADR-002 §5: this is the part of the reference implementation's token store that
is genuinely domain-free AND genuinely correct. Its *write* does not move -
``write_through_guard`` is truncate-in-place with no ``fsync``, and publishing it
as the fleet's durable write would give four future consumers a durability
guarantee it does not have.

``private_umask`` deliberately does NOT live here either: ADR-004 §3 replaces
umask-plus-chmod with mode-from-the-creating-syscall, and offering the rejected
mechanism to future consumers is the same mistake one level down.

Nothing here names a file the consumer owns. The mode check ITERATES the
directory, so the guarantee does not silently stop guaranteeing anything the day
the layout gains a file.
"""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

#: The store directory grants nothing to group or other.
STORE_DIRECTORY_MODE = 0o700

#: Every file directly in the store grants nothing to group or other.
STORE_FILE_MODE = 0o600

#: The advisory lock, created at 0600 so the service's own privacy check cannot
#: false-alarm on a healthy host (ADR-004 §3). The name carries no consumer's
#: word in it: this layer is shared, and a lock named for one service is a lock
#: the next four have to rename.
LOCK_FILE_NAME = ".store.lock"

#: The bits that grant anything at all to group or to other. A mode is private
#: exactly when none of them is set.
SHARED_BITS = 0o077


class ModeNotHonoured(RuntimeError):
    """The filesystem accepted a permission change and did not apply it.

    A substrate LIE rather than a wrong state, and the reason every mode claim in
    this repository is read back off the machine rather than inferred from a
    ``chmod`` that returned zero.

    Carries the path and the two modes. No file CONTENT, ever - the file whose
    mode is wrong is the one holding the credential.
    """

    def __init__(self, path: Path, wanted: int, observed: int) -> None:
        """Record what was asked for and what the machine actually reports.

        Args:
            path: The entry whose mode did not stick.
            wanted: The mode that was requested.
            observed: The mode read back off the filesystem afterwards.
        """
        super().__init__(f"{path} was set to {wanted:04o} and reads back as {observed:04o}")
        self.path = path
        self.wanted = wanted
        self.observed = observed


@dataclass(frozen=True)
class ModeEnforcement:
    """What making the store private actually had to change.

    Attributes:
        directory_repaired: Whether the directory itself was granting anything.
        files_repaired: The entries that were granting something, by name.
    """

    directory_repaired: bool = False
    files_repaired: tuple[str, ...] = ()

    def repaired_anything(self) -> bool:
        """Whether the world had to be changed for the contract to hold."""
        return self.directory_repaired or bool(self.files_repaired)


@contextmanager
def store_lock(directory: Path) -> Iterator[None]:
    """Hold an advisory ``flock`` across the load-refresh-commit section.

    The lock file is created at ``0600`` by the creating syscall rather than
    chmod-ed afterwards, so it cannot fail the service's own privacy check even
    for the instant between the two calls.

    Args:
        directory: The store directory.

    Yields:
        Nothing. The lock is held for the duration of the block.
    """
    path = directory / LOCK_FILE_NAME
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, STORE_FILE_MODE)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def enforce_store_modes(directory: Path) -> ModeEnforcement:
    """Make the directory and every file in it private, and verify by reading back.

    The check **iterates** and never names a document: naming a file means the
    guarantee silently stops guaranteeing anything the day the layout changes.
    Modes are read back off the filesystem, never inferred from a ``chmod`` that
    returned zero.

    Args:
        directory: The store directory.

    Returns:
        What had to be changed, so the caller can report a repair rather than
        performing one silently.

    Raises:
        ModeNotHonoured: When a mode was accepted and did not stick.
    """
    return ModeEnforcement(
        directory_repaired=enforce_directory_mode(directory),
        files_repaired=enforce_file_modes(directory),
    )


def enforce_directory_mode(directory: Path) -> bool:
    """Make the directory itself private, and verify by reading back.

    Separate from the files, because they are two different questions with two
    different answers: a directory that grants access to everyone and a file that
    does are distinct faults an operator fixes differently, and a check that
    repaired both at once would make the second unobservable.

    Args:
        directory: The store directory.

    Returns:
        Whether it was granting anything before the change.

    Raises:
        ModeNotHonoured: When the mode was accepted and did not stick.
    """
    return _make_private(directory, STORE_DIRECTORY_MODE)


def enforce_file_modes(directory: Path) -> tuple[str, ...]:
    """Make every file directly in the directory private, and verify by reading back.

    ITERATES, and never names a document.

    Args:
        directory: The store directory.

    Returns:
        The names that were granting something, sorted.

    Raises:
        ModeNotHonoured: When a mode was accepted and did not stick.
    """
    return tuple(entry.name for entry in _files_in(directory) if _make_private(entry, STORE_FILE_MODE))


def shared_files(directory: Path) -> tuple[str, ...]:
    """Every file directly in the directory that grants something to somebody else.

    Args:
        directory: The store directory.

    Returns:
        The offending names, sorted. Empty when the store is private.
    """
    return tuple(entry.name for entry in _files_in(directory) if _is_shared(entry))


def is_shared(path: Path) -> bool:
    """Whether an entry grants anything at all to group or to other.

    Args:
        path: The entry to read.

    Returns:
        True when any group or other bit is set.
    """
    return _is_shared(path)


def mode_of(path: Path) -> int:
    """The permission bits of an entry, read back off the filesystem."""
    return stat.S_IMODE(os.stat(path).st_mode)


def _files_in(directory: Path) -> tuple[Path, ...]:
    """Every file directly in a directory, sorted, links excluded."""
    return tuple(sorted(entry for entry in directory.iterdir() if entry.is_file() and not entry.is_symlink()))


def _is_shared(path: Path) -> bool:
    """Whether an entry's mode grants anything to group or other."""
    return bool(mode_of(path) & SHARED_BITS)


def _make_private(path: Path, wanted: int) -> bool:
    """Set an entry's mode and prove by reading it back that the change stuck.

    Args:
        path: The entry to make private.
        wanted: The mode it must end up at.

    Returns:
        Whether the entry was granting something before the change.

    Raises:
        ModeNotHonoured: When the entry STILL grants something to group or other
            after the change - the substrate accepted the call and did not apply
            it. Not "when the mode reads back as something else": an already
            private entry is never chmod-ed at all, and a filesystem that
            normalises the exact bits while removing the shared ones has done the
            job asked of it.
    """
    was_shared = _is_shared(path)
    if not was_shared:
        return False
    os.chmod(path, wanted)
    observed = mode_of(path)
    if observed & SHARED_BITS:
        raise ModeNotHonoured(path, wanted, observed)
    return True
