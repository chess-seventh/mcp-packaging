"""Structured events, namespaced ``<domain>.<thing>``, written for the operator.

ADR-002 §1: the base enum carries the three generic members and ``emit_event``
widens to ``EventName | str`` so a consumer can extend without the shared layer
learning a domain word.

C8 is absolute here: no event carries a token, a prefix, a suffix, a length or a
hash of one, and no event carries a request or response body. The mechanism is
that ``emit_event`` writes exactly the fields it is handed - so a field carrying a
credential is a visible call-site defect rather than a rendering somebody has to
notice.

Two sinks, one call. A JSON line on standard error is what the journal keeps; an
in-process ring is what a check can read back. The ring is bounded, because a
service answering for months must not grow a list per request.
"""

from __future__ import annotations

import json
import sys
from collections import deque
from enum import StrEnum
from threading import Lock
from typing import Any

#: The field every event carries, naming which event it is.
EVENT_FIELD = "event"

#: How many further events of the same name were deliberately NOT written. The
#: field exists so a cap is visible rather than silent: a record that stops writing
#: and says nothing is a count that lies by omission.
SUPPRESSED_FIELD = "suppressed"

#: How many events the in-process ring remembers. Bounded because this process runs
#: for months; the ring is a diagnostic, not a journal.
RECORDED_EVENT_LIMIT = 1024


class EventName(StrEnum):
    """The three events every consumer of this layer emits."""

    STARTUP_REFUSED = "health.startup.refused"
    AUTH_REJECTED = "http.auth.rejected"
    TOOL_CALL = "tool.call"


_recorded: deque[dict[str, Any]] = deque(maxlen=RECORDED_EVENT_LIMIT)
_lock = Lock()


def emit_event(name: EventName | str, **fields: Any) -> None:
    """Write one structured event to the journal.

    Args:
        name: The event name, namespaced ``<domain>.<thing>``.
        **fields: The event's fields. Never a credential, a body, or a hash.
    """
    event: dict[str, Any] = {EVENT_FIELD: _name_of(name), **fields}
    with _lock:
        _recorded.append(event)
    _write_to_the_journal(event)


def note_suppressed_event(name: EventName | str) -> None:
    """Record that one further event of this name was deliberately not written.

    The counter goes onto the most recent event of that name, so what was written
    and what is being held are read from the same line. That is what makes the
    accounting an IDENTITY - written plus held equals what arrived - rather than a
    number nobody can check.

    Args:
        name: The event name whose further occurrences are being held.
    """
    wanted = _name_of(name)
    with _lock:
        for event in reversed(_recorded):
            if event[EVENT_FIELD] == wanted:
                event[SUPPRESSED_FIELD] = int(event.get(SUPPRESSED_FIELD, 0)) + 1
                return


def recorded_events(name: EventName | str | None = None) -> tuple[dict[str, Any], ...]:
    """Read back the events emitted in this process.

    Args:
        name: Filter to one event name, or None for all of them.

    Returns:
        The events, oldest first. Copies, so a reader cannot edit the record.
    """
    wanted = None if name is None else _name_of(name)
    with _lock:
        return tuple(dict(event) for event in _recorded if wanted is None or event[EVENT_FIELD] == wanted)


def reset_recorded_events() -> None:
    """Clear the in-process ring. A per-boot counter, reset per scenario."""
    with _lock:
        _recorded.clear()


def _name_of(name: EventName | str) -> str:
    """The wire spelling of an event name, whichever shape it arrived in."""
    return name.value if isinstance(name, EventName) else str(name)


def _write_to_the_journal(event: dict[str, Any]) -> None:
    """One line on standard error, which is what the journal keeps.

    ``default=str`` rather than a raising encoder: an event that cannot be rendered
    must not take the request down with it, and a field rendered as its ``str`` is
    still the operator's answer.
    """
    print(json.dumps(event, sort_keys=True, default=str), file=sys.stderr, flush=True)
