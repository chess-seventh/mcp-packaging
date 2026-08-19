"""The transport seam: one MCP server object behind two driving adapters.

ADR-002 §1 and ADR-007 §4. The socket is bound **before** the ASGI application is
built, so an ``OSError`` becomes a named ``BindFailure`` rather than a traceback,
and the socket is closed in a ``finally`` so nothing is left half-listening.

The tool surface is identical across transports **by construction**: one
``Server`` object, never copied.

The caller check is a REQUIRED parameter of every function here that opens a
listener. Not defaulted, not optional, not omittable - an unauthenticated network
listener must not be expressible, and a default is exactly how that guarantee is
lost one refactor later.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from enum import StrEnum
from typing import Any, Protocol, cast

from mcp_packaging.bearer import (
    ASGIApplication,
    CallerCheckRequired,
    RejectionReason,
    guard_asgi_app_with_verifier,
)


class McpServer(Protocol):
    """The two things this layer asks of the one MCP server object.

    A Protocol rather than the vendor's class, and rather than ``object``. The
    vendor's class is deliberately not imported at module level - it is the
    heaviest import in the package and this module is on the startup path - and
    ``object`` was the shortcut taken instead. That shortcut cost three
    suppressed type errors, and a suppression is a claim nobody checks: the
    layer's real requirement of the server was written in a comment rather than
    in a type.
    """

    async def run(self, read_stream: Any, write_stream: Any, options: Any) -> Any:
        """Serve one session over a pair of streams."""
        ...

    def create_initialization_options(self) -> Any:
        """The options that session is opened with."""
        ...


#: Loopback, from the moment the module first exists (C6). A default this layer
#: MAY hold, because "reaches nothing off this machine" is its own promise to
#: every consumer rather than any consumer's fact.
DEFAULT_HOST = "127.0.0.1"

# ⚠ THERE IS NO `DEFAULT_PORT` HERE, AND ITS ABSENCE IS THE BOUNDARY RULE BITING.
# The code this moved from carried one, and it was the port assigned to a single
# server - an operator's allocation rather than anything this layer can know. A
# shared default would hand every OTHER server a port already taken, so `port` is
# a required argument of every function below precisely so nobody can take one by
# accident. Where the allocation is recorded is the business of whatever
# repository owns that fleet's configuration, and it is not this one.

#: The single MCP path. There is no other route, authenticated or not (C5).
MCP_PATH = "/mcp"

#: How many connections may wait while one is being accepted.
LISTEN_BACKLOG = 64

#: The one word a service manager wants when a unit is ready. The ADDRESS to send
#: it to arrives as a parameter: this layer never names an environment variable
#: (ADR-002 §1), not even the manager's own, and the composition root is the only
#: place that reads one.
READY_MESSAGE = b"READY=1"


class TransportKind(StrEnum):
    """The two ways a caller reaches this server.

    ``STDIO`` is the default and its authentication boundary is the OS process
    boundary; it must not gain a token check. ``HTTP`` is bearer-guarded and the
    guard is not optional.
    """

    STDIO = "stdio"
    HTTP = "http"


class BindFailure(RuntimeError):
    """The socket could not be taken, named rather than dumped.

    Carries the host, the port, the OS's own ``strerror`` and the remedy.
    """

    def __init__(self, host: str, port: int, reason: str) -> None:
        """Record what could not be bound and why.

        Args:
            host: The address that could not be bound.
            port: The port that could not be taken.
            reason: The OS's own message for the failure.
        """
        super().__init__(
            f"cannot listen on {host}:{port}: {reason}. Choose a different port, or stop whatever is holding this one."
        )
        self.host = host
        self.port = port
        self.reason = reason


def build_http_application(
    server: McpServer,
    *,
    host: str,
    port: int,
    verifier: Callable[[str | None], RejectionReason | None],
) -> ASGIApplication:
    """Build the guarded ASGI application for the MCP session manager.

    The guard goes in front of the WHOLE application rather than in front of a list
    of paths. There is no health, readiness, metrics or root route that answers
    without the secret, and there is none because none can be added without also
    adding it behind the guard (C5).

    Args:
        server: The one MCP ``Server`` object, shared with the stdio adapter.
        host: The address the socket is bound to.
        port: The port the socket is bound to.
        verifier: The caller check. **Required, no default** - there must be no
            way to express an unauthenticated network listener.

    Returns:
        The ASGI application, with the guard already in front of it.

    Raises:
        CallerCheckRequired: When no caller check was supplied. Raised BEFORE
            anything is constructed, so a request for an unauthenticated listener
            produces no listener, no session manager and no application.
    """
    if verifier is None:
        raise CallerCheckRequired()
    return guard_asgi_app_with_verifier(_session_application(server), verifier)


def serve_http(
    server: McpServer,
    *,
    host: str,
    port: int,
    verifier: Callable[[str | None], RejectionReason | None],
    ready_address: str | None = None,
) -> None:
    """Bind the socket, then signal readiness, then serve.

    Readiness is signalled only once the socket is accepting, so
    ``systemctl is-active`` is not a lie. The socket is taken FIRST and the
    application is built after: binding is the step that can fail for a reason an
    operator can act on, and it must fail as a named refusal rather than as a
    traceback out of a framework.

    Args:
        server: The one MCP ``Server`` object.
        host: The address to bind.
        port: The port to take.
        verifier: The caller check. Required, no default.
        ready_address: Where to send the readiness notification, when something is
            listening for one. A VALUE, not a variable this layer knows the name of.

    Raises:
        BindFailure: When the socket cannot be taken.
        CallerCheckRequired: When no caller check was supplied.
    """
    listener = bind(host, port)
    try:
        application = build_http_application(server, host=host, port=port, verifier=verifier)
        notify_ready(ready_address)
        _run_asgi(application, listener)
    finally:
        listener.close()


def serve_stdio(server: McpServer) -> None:
    """Serve the same tools over stdio, with no caller check and no listener.

    No caller check, deliberately. A local session's authentication boundary IS the
    operating system's process boundary; adding a token there is a lock on the
    inside of a door that is already the wall, and it would make the two transports
    look uniform while protecting nothing.
    """
    import anyio
    from mcp.server.stdio import stdio_server

    async def serve() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    anyio.run(serve)


def bind(host: str, port: int) -> socket.socket:
    """Take the socket, or refuse by name.

    Args:
        host: The address to bind.
        port: The port to take.

    Returns:
        The bound, listening socket.

    Raises:
        BindFailure: Carrying the address, the port, the OS's own message and the
            remedy - because an operator reading a journal cannot guess any of the
            four from a traceback.
    """
    listener = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((host, port))
        listener.listen(LISTEN_BACKLOG)
    except OSError as failure:
        listener.close()
        raise BindFailure(host, port, failure.strerror or str(failure)) from None
    return listener


def notify_ready(address: str | None) -> None:
    """Tell the service manager the listener is accepting, if one is listening.

    Sent AFTER the socket is bound and listening, never before: the kernel accepts
    into the backlog from that instant, so anything waiting on this unit is waiting
    on something real. A ``Type=simple`` unit would report active the moment the
    process existed, and its waiters would race their own subject.

    Args:
        address: The manager's socket, or None when there is no manager. A value
            rather than a variable name, because this layer names none.

    Silent when there is nothing listening. A development shell is not a failure.
    """
    if not address:
        return
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
        notifier.connect("\0" + address[1:] if address.startswith("@") else address)
        notifier.sendall(READY_MESSAGE)


def _session_application(server: McpServer) -> ASGIApplication:
    """The MCP session manager, as an ASGI application, over the ONE server object.

    The server object is passed through rather than copied. That is the whole of
    "the tool surface is identical whichever way the caller arrives": there is one
    surface because there is one object.
    """
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    # The vendor's manager is annotated against its own concrete Server class,
    # not against a protocol, so no structural type can satisfy it. Cast at this
    # one boundary rather than widen the parameter: every other function in this
    # module keeps the protocol, and the place the vendor's nominal requirement
    # bites is one line long and named.
    manager = StreamableHTTPSessionManager(app=cast("Any", server))

    async def application(scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] == "lifespan":
            await _hold_the_session_manager_open(manager, receive, send)
            return
        await manager.handle_request(scope, receive, send)

    return application


async def _hold_the_session_manager_open(manager: Any, receive: Callable, send: Callable) -> None:
    """Enter the session manager's own context and stay in it while the server runs.

    ⚠ WITHOUT THIS THE SERVER 401s CORRECTLY AND 500s ON EVERY AUTHENTICATED
    REQUEST. The manager's task group is created by ``run()``; constructing the
    manager does not create it, and ``handle_request`` raises "Task group is not
    initialized. Make sure to use run()." the moment a caller who HOLDS the secret
    arrives. So the failure lands exactly on the callers the whole bearer guard
    exists to admit, and never on the ones it exists to refuse.

    The manager's lifetime is the PROCESS's, which in ASGI is the lifespan scope -
    not a request, and not something a synchronous factory can hold. That is why
    the transport asks uvicorn for ``lifespan="on"``: with it off, this branch is
    never entered and there is nowhere else the context could be opened.

    Args:
        manager: The MCP session manager.
        receive: The ASGI receive channel.
        send: The ASGI send channel.
    """
    await receive()  # lifespan.startup
    async with manager.run():
        await send({"type": "lifespan.startup.complete"})
        while True:
            message = await receive()
            if message["type"] == "lifespan.shutdown":
                break
    await send({"type": "lifespan.shutdown.complete"})


def _run_asgi(application: ASGIApplication, listener: socket.socket) -> None:
    """Serve the application on an already-bound socket.

    It sends no readiness notification - :func:`serve_http` has already done that,
    once the socket was accepting, which is what makes ``Type=notify`` honest.
    This docstring used to claim the notification, which put the one line an
    operator would go looking for in the wrong function.
    """
    import uvicorn

    # ``lifespan="on"``, NOT "off". The session manager's task group is created by
    # its own async context manager, and the process lifetime is the only scope
    # that context can span - so turning the lifespan protocol off removed the one
    # hook able to open it, and every authenticated request 500'd.
    config = uvicorn.Config(application, log_level="warning", lifespan="on")
    uvicorn.Server(config).run(sockets=[listener])
