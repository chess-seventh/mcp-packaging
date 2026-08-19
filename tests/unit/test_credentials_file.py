"""The credentials parse and the requirement check. Pure, so plain function tests.

Every function here is an ADR-002 §7 "pure" contract shape: no observable
mutation, no I/O, no environment. (Two of them are the ones §7 names; the four
message builders are pure for the same reason and are covered here too.)

The file *reading* stays in a consumer's composition root, which is why nothing
here opens anything.
"""

from __future__ import annotations

import pytest

from mcp_packaging.credentials_file import (
    CredentialsIncomplete,
    absent_message,
    parse,
    refusal_message,
    require,
    source_message,
)


@pytest.mark.contract_shape_pure_function
def test_a_plain_assignment_is_read() -> None:
    assert parse("NAME=value") == {"NAME": "value"}


@pytest.mark.contract_shape_pure_function
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("export NAME=value", {"NAME": "value"}),
        ('NAME="value"', {"NAME": "value"}),
        ("NAME='value'", {"NAME": "value"}),
        ("  NAME = value  ", {"NAME": "value"}),
        ("# a comment\nNAME=value", {"NAME": "value"}),
        ("\n\nNAME=value\n\n", {"NAME": "value"}),
        ("NAME=a=b=c", {"NAME": "a=b=c"}),
        ('NAME="unbalanced', {"NAME": '"unbalanced'}),
        ("A=1\nB=2", {"A": "1", "B": "2"}),
    ],
)
def test_the_shapes_a_rendered_or_hand_written_file_really_carries(text: str, expected: dict[str, str]) -> None:
    """Each case is a shape a credentials file picks up in the wild.

    `NAME=a=b=c` is the one worth naming: only the FIRST `=` separates, because a
    secret is allowed to contain one and a parser that split on every `=` would
    quietly truncate it.
    """
    assert parse(text) == expected


@pytest.mark.contract_shape_pure_function
def test_a_key_with_an_empty_value_is_kept_rather_than_dropped() -> None:
    """ "Present but empty" and "absent" are materially different, and only
    `require` may collapse them. A parser that dropped the blank would make the
    realistic template typo indistinguishable from a missing line."""
    assert parse("NAME=") == {"NAME": ""}


@pytest.mark.contract_shape_pure_function
def test_a_line_that_assigns_nothing_is_not_an_assignment() -> None:
    assert parse("# NAME=value\nnot an assignment\n") == {}


@pytest.mark.error
def test_a_missing_key_is_refused_by_name() -> None:
    with pytest.raises(CredentialsIncomplete) as refusal:
        require({"A": "1"}, ["A", "B"])
    assert refusal.value.missing_key == "B"


@pytest.mark.error
def test_a_present_but_empty_key_counts_as_missing() -> None:
    """A blank line in a rendered file is the realistic typo. Carrying it forward
    means presenting an empty secret and reading the provider's refusal as a
    credential problem it is not."""
    with pytest.raises(CredentialsIncomplete) as refusal:
        require({"A": ""}, ["A"])
    assert refusal.value.missing_key == "A"


@pytest.mark.property
def test_no_refusal_message_carries_a_value() -> None:
    """A message names its PATH or its VARIABLE, and never a value.

    ⚠ THE SECRET IS PUT WHERE THE FUNCTIONS COULD REACH IT. An earlier version
    declared a secret and never passed it to anything, so `secret not in message`
    could not have failed for any implementation - it asserted about a string the
    code had never seen. These four functions take a path and a key, so a path
    and a key is how a value would reach them.

    The second half is a DISJUNCTION and now says so: `source_message` and
    `absent_message` name only a path, `CredentialsIncomplete` names only a key,
    and only `refusal_message` names both.
    """
    secret = "SYNTHETIC-VALUE-THAT-MUST-NOT-APPEAR-8f2a"

    # A path IS named, deliberately: a path is not a secret and it is the one
    # thing an operator needs in order to go and fix the fault.
    assert secret in source_message(f"/run/secrets/{secret}.env")

    # A KEY is named, and its value never is.
    assert secret not in refusal_message("/run/secrets/x.env", "TOKEN")
    assert secret not in str(CredentialsIncomplete("TOKEN"))
    assert "TOKEN" in refusal_message("/run/secrets/x.env", "TOKEN")
    assert "TOKEN" in str(CredentialsIncomplete("TOKEN"))
    assert "/run/secrets/x.env" in absent_message("/run/secrets/x.env")
