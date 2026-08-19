"""The caller check: what it refuses, what it returns, and how much work it does.

ADR-002 §7 makes two claims about this module that ordinary tests cannot reach,
and both are covered here:

* the comparison is `hmac.compare_digest` - pinned by an AST check, because a
  `compare_digest` -> `==` mutant is behaviourally EQUIVALENT and survives
  mutation testing. Only a source-shape check can hold this one;
* **every rejection class runs one comparison**, so no way of failing skips work
  another way of failing performs. Byte-identical responses do not close a timing
  channel; identical work is the claim, and it is asserted by counting.
"""

from __future__ import annotations

import ast
import asyncio
import pathlib

import pytest

from mcp_packaging import bearer
from mcp_packaging.bearer import (
    MINIMUM_TOKEN_LENGTH,
    CallerCheckRequired,
    RejectionReason,
    guard_asgi_app_with_verifier,
    unauthorized_response_bytes,
    verify_bearer_token,
)
from mcp_packaging.events import EventName, recorded_events, reset_recorded_events

SECRET = "S" * MINIMUM_TOKEN_LENGTH
BEARER_SOURCE = pathlib.Path(bearer.__file__)


@pytest.fixture(autouse=True)
def _clean_record() -> None:
    """A per-boot counter, so each test starts from an empty record."""
    reset_recorded_events()


@pytest.mark.contract_shape_pure_function
def test_the_right_secret_is_admitted() -> None:
    """The one accepted shape returns None, which is what "admitted" means here."""
    assert verify_bearer_token(f"Bearer {SECRET}", SECRET) is None


@pytest.mark.error
@pytest.mark.parametrize(
    ("presented", "expected"),
    [
        (None, RejectionReason.MISSING_HEADER),
        ("", RejectionReason.MALFORMED_HEADER),
        ("Basic abcdefgh", RejectionReason.MALFORMED_HEADER),
        ("Bearer", RejectionReason.MALFORMED_HEADER),
        ("Bearer    ", RejectionReason.MALFORMED_HEADER),
        ("bearer " + SECRET, RejectionReason.MALFORMED_HEADER),
        ("Bearer wrong-but-long-enough-to-be-plausible", RejectionReason.BAD_TOKEN),
    ],
)
def test_every_refused_shape_is_classified_locally(presented: str | None, expected: RejectionReason) -> None:
    """The class is written down for the operator, and never returned to the caller."""
    assert verify_bearer_token(presented, SECRET) is expected


@pytest.mark.error
def test_a_server_with_no_secret_configured_admits_nobody() -> None:
    """Not even the dummy the absent case compares against.

    The presented dummy and the expected dummy are DIFFERENT values on purpose:
    if they were the same, a caller who guessed the padding would be admitted to a
    server that had no secret at all - which is the worst-configured server there
    is, and the one that must be hardest to reach.
    """
    assert verify_bearer_token(f"Bearer {'\x00' * MINIMUM_TOKEN_LENGTH}", "") is RejectionReason.BAD_TOKEN
    assert verify_bearer_token(None, "") is RejectionReason.MISSING_HEADER


@pytest.mark.property
def test_every_rejection_class_performs_exactly_one_comparison(monkeypatch: pytest.MonkeyPatch) -> None:
    """The timing claim, asserted by COUNTING rather than by inspection.

    S4 claims "the malformed-header path does not short-circuit measurably
    relative to the wrong-token path". Pinning `compare_digest` does not deliver
    that on its own: a missing header, a malformed header and a wrong scheme are
    all classified BEFORE any comparison would run. So the guard runs one
    comparison in every class, and this counts them.
    """
    calls: list[int] = []
    real = bearer.hmac.compare_digest

    def counted(left: bytes, right: bytes) -> bool:
        calls.append(1)
        return real(left, right)

    monkeypatch.setattr(bearer.hmac, "compare_digest", counted)

    for presented in (None, "", "Basic x", "Bearer wrong-but-long-enough-to-be-plausible", f"Bearer {SECRET}"):
        calls.clear()
        verify_bearer_token(presented, SECRET)
        assert sum(calls) == 1, f"{presented!r} performed {sum(calls)} comparisons, not exactly one"


@pytest.mark.property
def test_the_refusal_is_byte_identical_across_every_class() -> None:
    """One refusal. A caller cannot tell "no secret here" from "your secret is wrong"."""
    responses = [_refusal_bytes(presented) for presented in (None, "", "Basic x", "Bearer wrong-value-here-ok")]
    assert len(set(responses)) == 1
    assert responses[0] == unauthorized_response_bytes()


@pytest.mark.error
def test_a_listener_cannot_be_asked_for_without_a_caller_check() -> None:
    """Raised rather than defaulted: the unauthenticated listener is not expressible."""
    with pytest.raises(CallerCheckRequired):
        guard_asgi_app_with_verifier(_nothing, None)  # ty: ignore[invalid-argument-type]


@pytest.mark.error
def test_the_rejection_record_is_capped_and_says_what_it_held() -> None:
    """A caller must not be able to fill the journal by guessing in a loop.

    What was written PLUS what is held equals what arrived, and both numbers come
    off the same record - so the accounting is an identity rather than a claim
    about two counters that could disagree.
    """
    arrived = bearer.RECORDED_REJECTION_LIMIT + 7
    for _ in range(arrived):
        verify_bearer_token(None, SECRET)

    written = recorded_events(EventName.AUTH_REJECTED)
    assert len(written) == bearer.RECORDED_REJECTION_LIMIT
    held = sum(int(event.get("suppressed", 0)) for event in written)
    assert len(written) + held == arrived


@pytest.mark.property
def test_no_rejection_event_carries_anything_of_the_secret() -> None:
    """C8: not the value, not a prefix, not a length, not a hash."""
    verify_bearer_token(f"Bearer {SECRET}-wrong", SECRET)
    for event in recorded_events(EventName.AUTH_REJECTED):
        rendered = repr(event)
        assert SECRET not in rendered
        assert SECRET[:8] not in rendered


@pytest.mark.property
def test_the_comparison_is_still_hmac_compare_digest() -> None:
    """A source-shape check, because behaviour cannot see this one.

    ⚠ THIS IS THE TEST ADR-002 §1 SAYS MUST MOVE WITH THE MODULE, and it did not
    exist in the reference implementation - the ADR named it and nothing built it.
    Replacing `hmac.compare_digest(a, b)` with `a == b` changes no observable
    behaviour of this module, so every behavioural test and every mutant survives
    it. Only the source shape says whether the comparison is constant-time.
    """
    tree = ast.parse(BEARER_SOURCE.read_text())
    comparisons = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "compare_digest"
    ]
    assert len(comparisons) == 1, "the module must compare exactly once, with hmac.compare_digest"

    equality = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Compare)
        and any(isinstance(operator, ast.Eq | ast.NotEq) for operator in node.ops)
        and _mentions_a_secret(node)
    ]
    assert equality == [], "a secret is compared with == somewhere; only compare_digest may touch one"


def _mentions_a_secret(node: ast.AST) -> bool:
    """Whether an expression names one of the two secret-bearing locals."""
    return any(
        isinstance(child, ast.Name) and child.id in {"presented", "expected", "candidate", "token"}
        for child in ast.walk(node)
    )


def _refusal_bytes(presented: str | None) -> bytes:
    """Drive the guard once and collect exactly what it puts on the wire."""
    sent: list[dict] = []

    async def send(message: dict) -> None:
        sent.append(message)

    guarded = guard_asgi_app_with_verifier(_nothing, lambda value: verify_bearer_token(value, SECRET))
    headers = () if presented is None else ((b"authorization", presented.encode("latin-1")),)
    asyncio.run(guarded({"type": "http", "headers": list(headers)}, _nothing_receive, send))

    start, body = sent
    return (
        str(start["status"]).encode("ascii")
        + b"\r\n"
        + b"".join(name + b": " + value + b"\r\n" for name, value in start["headers"])
        + b"\r\n"
        + body["body"]
    )


async def _nothing(scope: dict, receive: object, send: object) -> None:
    """An application that must never be reached by a refused caller."""
    raise AssertionError("a refused caller reached the application behind the guard")


async def _nothing_receive() -> dict:
    """A receive channel nothing on the refusal path ever pulls from."""
    return {}
