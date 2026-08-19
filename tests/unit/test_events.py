"""Structured events: what they carry, and how a cap accounts for itself.

C8 is absolute: no event carries a token, a prefix, a suffix, a length or a hash
of one, and none carries a request or response body. The mechanism is that
`emit_event` writes exactly the fields it is handed, so a field carrying a
credential is a visible call-site defect rather than a rendering somebody has to
notice - and that is what these tests hold.
"""

from __future__ import annotations

import json
from enum import StrEnum

import pytest

from mcp_packaging.events import (
    EVENT_FIELD,
    RECORDED_EVENT_LIMIT,
    SUPPRESSED_FIELD,
    EventName,
    emit_event,
    note_suppressed_event,
    recorded_events,
    reset_recorded_events,
)


class ConsumerEvent(StrEnum):
    """A consumer's extension. Already namespaced `<domain>.<thing>`, which is why
    an open vocabulary works here without a registry."""

    RENEWED = "grant.renewed"


@pytest.fixture(autouse=True)
def _clean_record() -> None:
    reset_recorded_events()


@pytest.mark.property
def test_an_event_carries_its_name_and_exactly_the_fields_it_was_handed() -> None:
    emit_event(EventName.TOOL_CALL, tool="ping")
    assert recorded_events() == ({EVENT_FIELD: "tool.call", "tool": "ping"},)


@pytest.mark.boundary
def test_a_consumer_may_emit_its_own_event_name() -> None:
    """`emit_event` widens to `EventName | str` so a consumer extends without this
    layer learning a domain word."""
    emit_event(ConsumerEvent.RENEWED, at=1)
    emit_event("plain.string", at=2)
    assert [event[EVENT_FIELD] for event in recorded_events()] == ["grant.renewed", "plain.string"]


@pytest.mark.property
def test_the_record_is_filtered_by_name() -> None:
    emit_event(EventName.TOOL_CALL)
    emit_event(EventName.AUTH_REJECTED, reason="bad_token")
    emit_event(EventName.TOOL_CALL)
    assert len(recorded_events(EventName.TOOL_CALL)) == 2
    assert len(recorded_events(EventName.AUTH_REJECTED)) == 1


@pytest.mark.property
def test_a_reader_cannot_edit_the_record() -> None:
    """Copies out, so a caller inspecting the ring cannot rewrite the journal's
    in-process twin."""
    emit_event(EventName.TOOL_CALL, tool="ping")
    read = recorded_events()
    read[0]["tool"] = "tampered"
    assert recorded_events()[0]["tool"] == "ping"


@pytest.mark.property
def test_the_suppression_count_lands_on_an_event_of_that_name_and_no_other() -> None:
    """What was written and what is being held are read off the SAME line, which
    is what makes the accounting an identity rather than two numbers that could
    disagree.

    ⚠ NOT "the most recent", which this was called: one event of that name exists
    here, so first-match and last-match are indistinguishable. What the body does
    pin is that the count lands on that name and not on the other one.
    """
    emit_event(EventName.AUTH_REJECTED, reason="bad_token")
    emit_event(EventName.TOOL_CALL)
    note_suppressed_event(EventName.AUTH_REJECTED)
    note_suppressed_event(EventName.AUTH_REJECTED)

    rejected = recorded_events(EventName.AUTH_REJECTED)
    assert rejected[-1][SUPPRESSED_FIELD] == 2
    assert SUPPRESSED_FIELD not in recorded_events(EventName.TOOL_CALL)[0]


@pytest.mark.property
def test_suppressing_a_name_that_was_never_written_records_nothing() -> None:
    note_suppressed_event(EventName.AUTH_REJECTED)
    assert recorded_events() == ()


@pytest.mark.property
def test_the_ring_is_bounded_because_this_process_runs_for_months() -> None:
    """A service answering for months must not grow a list per request. The ring
    is a diagnostic, not a journal - the journal is the JSON on stderr."""
    for index in range(RECORDED_EVENT_LIMIT + 50):
        emit_event(EventName.TOOL_CALL, index=index)
    events = recorded_events()
    assert len(events) == RECORDED_EVENT_LIMIT
    assert events[-1]["index"] == RECORDED_EVENT_LIMIT + 49


@pytest.mark.property
def test_every_event_is_one_json_line_on_standard_error(capsys: pytest.CaptureFixture[str]) -> None:
    """One line, because that is what a journal keeps and what a reader greps."""
    emit_event(EventName.TOOL_CALL, tool="ping")
    written = capsys.readouterr().err.strip()
    assert "\n" not in written
    assert json.loads(written) == {EVENT_FIELD: "tool.call", "tool": "ping"}


@pytest.mark.error
def test_an_unrenderable_field_does_not_take_the_request_down(capsys: pytest.CaptureFixture[str]) -> None:
    """`default=str` rather than a raising encoder: an event that cannot be
    rendered must not become the failure, and a field rendered as its `str` is
    still the operator's answer."""

    class Opaque:
        def __str__(self) -> str:
            return "opaque"

    emit_event(EventName.TOOL_CALL, thing=Opaque())
    assert json.loads(capsys.readouterr().err.strip())["thing"] == "opaque"
