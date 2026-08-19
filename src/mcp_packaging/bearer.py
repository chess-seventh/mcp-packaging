"""The caller check that sits in front of the MCP session manager.

ADR-002 §7. Two properties this module owes and a comment cannot supply:

* the comparison is ``hmac.compare_digest``, pinned by an AST check because a
  ``compare_digest`` -> ``==`` mutant is behaviourally equivalent and survives
  mutation testing;
* **every rejection class runs one comparison**, or the two classes that would
  short-circuit differ in work from the one that does not, and the timing claim
  is unearned. Two of the three classes compare a fixed-length dummy because
  they have nothing real to compare; the third compares what the caller actually
  presented.

The shared layer never names an environment variable (ADR-002 §1); the variable
holding the secret is the consumer's, and arrives as a value.

The refusal is ONE response. Same status, same headers, same body, for every class
and for every path - so a caller cannot tell "there is no secret configured here"
from "your secret is wrong", which is the only thing an attacker needs. The class
is written down locally, for the operator, and is never returned.
"""

from __future__ import annotations

import hmac
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Any

from mcp_packaging.events import EventName, emit_event, note_suppressed_event, recorded_events

#: The floor a shared secret must clear before an HTTP listener may open.
#: The VALUE is DELIVER's to choose; the acceptance criterion is the property
#: ("a secret below the floor refuses the start"), asserted with a secret short
#: enough to be below any defensible floor.
MINIMUM_TOKEN_LENGTH = 32

#: The scheme this server accepts, and the one character that ends it.
BEARER_SCHEME = "Bearer"

#: The header a caller presents its credential in.
#: An ASGI application, as this layer needs to know it: a callable taking the
#: scope, a receive and a send, and awaiting. Named once so the guard's
#: parameter, its return and the transport that serves it all agree, and so
#: `object` stops travelling through the seam and turning into a type error
#: at the point it is finally handed to a server.
ASGIApplication = Callable[[dict, Callable[..., Any], Callable[..., Any]], Awaitable[None]]

AUTHORIZATION_HEADER = b"authorization"

#: What is compared when there is nothing real to compare. Fixed length, so the
#: three classes that already know they will fail do the SAME work as the one that
#: does not - identical bytes do not close a timing channel; identical work does.
_DUMMY_PRESENTED = "\x00" * MINIMUM_TOKEN_LENGTH

#: What a configured secret compares against when no secret is configured at all.
#: Distinct from the presented dummy, so "nothing is configured" can never be made
#: to match by presenting the dummy.
_DUMMY_EXPECTED = "\x01" * MINIMUM_TOKEN_LENGTH

#: How many refusals are written per boot before the record starts holding them.
#: A caller must not be able to fill the journal by presenting a wrong secret in a
#: loop.
#:
#: ⚠ The held ones are counted onto the last line of the IN-PROCESS RING, not
#: onto the journal - that line was printed and flushed before the cap was
#: reached. An operator reading journald sees the capped count and no marker;
#: what the count buys is an identity a check can assert. See
#: :data:`mcp_packaging.events.SUPPRESSED_FIELD`.
RECORDED_REJECTION_LIMIT = 20

#: The one refusal. Status, headers and body, spelled once so no class can differ.
UNAUTHORIZED_STATUS = 401
UNAUTHORIZED_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"www-authenticate", BEARER_SCHEME.encode("ascii")),
    (b"content-length", b"0"),
)
UNAUTHORIZED_BODY = b""


class RejectionReason(StrEnum):
    """Why a caller was refused. Logged locally, never returned.

    Three classes, four caller shapes: a wrong scheme and a malformed value are
    the same class. The response is byte-identical across all four regardless.
    """

    MISSING_HEADER = "missing_header"
    MALFORMED_HEADER = "malformed_header"
    BAD_TOKEN = "bad_token"


class CallerCheckRequired(RuntimeError):
    """A network listener was asked for with no caller check.

    Raised rather than defaulted. The strongest form of the guarantee is not "we
    always pass a check" but "there is no way to ask for a listener without one",
    and a default is exactly the way that guarantee is lost.
    """

    def __init__(self) -> None:
        """State what is missing, and that it has no default."""
        super().__init__("a network listener requires a caller check; there is no default and no way to omit one")


def verify_bearer_token(presented: str | None, expected: str) -> RejectionReason | None:
    """Classify an Authorization header value against the secret in force.

    Exactly ONE ``hmac.compare_digest`` runs on every path, including the two
    classes that already know the answer. Without that, those two are refused
    before any comparison happens at all and differ from the third in work by
    construction, which is the timing oracle the uniform response was supposed to
    close.

    Args:
        presented: The raw header value, or None when no header arrived.
        expected: The shared secret this server is configured with.

    Returns:
        None when the caller is accepted; otherwise the class of the refusal.
    """
    candidate, already_failed = _candidate(presented)
    matched = hmac.compare_digest(candidate.encode("utf-8"), _comparable(expected).encode("utf-8"))
    reason = already_failed if already_failed is not None else (None if matched else RejectionReason.BAD_TOKEN)
    if reason is not None:
        _record_rejection(reason)
    return reason


def guard_asgi_app_with_verifier(
    app: ASGIApplication,
    verifier: Callable[[str | None], RejectionReason | None],
) -> ASGIApplication:
    """Wrap an ASGI application so every request is checked before it reaches it.

    EVERY request, on every path. There is no health, readiness, metrics or root
    route that answers without the secret (C5): the guard is in front of the whole
    application rather than in front of a list of paths somebody keeps current.

    Args:
        app: The ASGI application to guard.
        verifier: The caller check. Required, with no default: an unauthenticated
            network listener must not be expressible.

    Returns:
        The guarded ASGI application.

    Raises:
        CallerCheckRequired: When no caller check was supplied.
    """
    if verifier is None:
        raise CallerCheckRequired()

    async def guarded(scope: dict, receive: Callable, send: Callable) -> None:
        """Refuse, or hand on. Nothing is constructed for a caller that fails."""
        if scope.get("type") != "http":
            await app(scope, receive, send)
            return
        if verifier(_header_value(scope)) is not None:
            await _refuse(send)
            return
        await app(scope, receive, send)

    return guarded


def unauthorized_response_bytes() -> bytes:
    """The whole refusal, as bytes, for a caller comparing one class against another.

    Spelled from the same constants the guard sends, so a byte comparison over the
    four caller SHAPES - three classes, since a wrong scheme and a malformed value
    are one - is a comparison of what actually goes on the wire.

    Returns:
        Status, headers and body, rendered once.
    """
    headers = b"".join(name + b": " + value + b"\r\n" for name, value in UNAUTHORIZED_HEADERS)
    return str(UNAUTHORIZED_STATUS).encode("ascii") + b"\r\n" + headers + b"\r\n" + UNAUTHORIZED_BODY


def _candidate(presented: str | None) -> tuple[str, RejectionReason | None]:
    """The value to compare, and the class this shape already fails as.

    A shape that already fails still yields a fixed-length candidate, because the
    comparison runs anyway. That is the whole mechanism behind "no way of failing
    skips work another way of failing performs".
    """
    if presented is None:
        return _DUMMY_PRESENTED, RejectionReason.MISSING_HEADER
    scheme, separator, token = presented.partition(" ")
    if not separator or scheme != BEARER_SCHEME or not token.strip():
        return _DUMMY_PRESENTED, RejectionReason.MALFORMED_HEADER
    return token.strip(), None


def _comparable(expected: str) -> str:
    """The configured secret, or a value nothing can be made to match.

    A server with no secret configured must not be reachable by presenting the
    dummy, so the absent case compares against a DIFFERENT fixed-length value.
    """
    return expected or _DUMMY_EXPECTED


def _header_value(scope: dict) -> str | None:
    """The Authorization header a request carried, or None when it carried none."""
    for name, value in scope.get("headers") or ():
        if name.lower() == AUTHORIZATION_HEADER:
            return value.decode("latin-1")
    return None


async def _refuse(send: Callable) -> None:
    """Send the one refusal. No status, body or header tells the classes apart."""
    await send({"type": "http.response.start", "status": UNAUTHORIZED_STATUS, "headers": list(UNAUTHORIZED_HEADERS)})
    await send({"type": "http.response.body", "body": UNAUTHORIZED_BODY})


def _record_rejection(reason: RejectionReason) -> None:
    """Write the class down locally, capped, and count what the cap held back.

    The class is written for the operator, so a pattern forming is visible in
    their own journal.
    Nothing of what the caller presented and nothing of what the server holds is
    written - not the value, not a prefix, not a length, not a hash.

    The cap is counted off the RECORD itself rather than off a private counter, so
    the two can never disagree: what was written plus what is held is then an
    identity over one set of numbers instead of a claim about two.
    """
    if len(recorded_events(EventName.AUTH_REJECTED)) < RECORDED_REJECTION_LIMIT:
        emit_event(EventName.AUTH_REJECTED, reason=reason.value)
        return
    note_suppressed_event(EventName.AUTH_REJECTED)
