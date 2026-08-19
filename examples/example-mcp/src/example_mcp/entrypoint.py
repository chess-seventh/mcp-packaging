"""The composition root, and the only impure module in this package.

It is the only place that reads the environment, opens a file, and wires
capabilities into pure functions. Everything it hands to the shared layer is a
VALUE - the layer names no environment variable of its own, so the four names
below are this consumer's and could not live anywhere else.

The invariant is **wire, then probe, then serve**. There is no code path from
"a probe refused" to "serve anyway".

⚠ WHAT THIS FILE IS FOR. It is the worked example of the boundary ADR-002 draws:
everything below is what a consumer must still write for itself, and everything
it imports from ``mcp_packaging`` is what it no longer has to. If this file grows
a mechanism rather than a wiring, that mechanism belongs on the other side of the
import.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from mcp_packaging import credentials_file
from mcp_packaging.bearer import MINIMUM_TOKEN_LENGTH, verify_bearer_token
from mcp_packaging.events import EventName, emit_event
from mcp_packaging.startup_probe import (
    ProbeCheck,
    ProbeCheckFn,
    StartupRefused,
    private_directory_check,
    private_files_check,
    shared_secret_check,
)
from mcp_packaging.startup_probe import run as run_startup_probe
from mcp_packaging.transport import DEFAULT_HOST, McpServer, TransportKind, serve_http, serve_stdio

#: Where the service manager listens for the readiness notification. Named HERE
#: rather than in the transport: the shared layer never names an environment
#: variable, not even the manager's own.
READY_NOTIFICATION_VARIABLE = "NOTIFY_SOCKET"

#: Where systemd puts the credential it loaded. A PATH, not a secret.
CREDENTIALS_DIRECTORY_VARIABLE = "EXAMPLE_MCP_CREDENTIALS_DIR"

#: The state area. A PATH, not a secret; set by the module to the state area.
STATE_VARIABLE = "EXAMPLE_MCP_STATE"

#: ⚠ THE ONLY SECRET THIS SERVER HOLDS, and that is what makes it the second
#: SHAPE rather than a second copy. The reference consumer's credentials file
#: carries four values; this one carries one, and every check still runs.
SHARED_SECRET_KEY = "EXAMPLE_MCP_AUTH_TOKEN"

#: The port this consumer claims. ⚠ NOT a default of the shared layer: a port is
#: a fleet fact and a shared default would hand every other server one already
#: taken.
DEFAULT_PORT = 8799

#: 78 is EX_CONFIG. A service manager reads a status, and it must be able to tell
#: a refused start from a crash.
EXIT_STARTUP_REFUSED = 78
EXIT_OK = 0


@dataclass
class Options:
    """What the console script was asked to do."""

    transport: str
    host: str
    port: int
    credentials_file: str
    state: str

    def http_selected(self) -> bool:
        """Whether the network transport was chosen, which is what needs a secret."""
        return self.transport == TransportKind.HTTP.value


def parse_arguments(argv: Sequence[str], environ: Mapping[str, str]) -> Options:
    """Turn the command line and the environment into options.

    The environment is a PARAMETER. Nothing here reaches for ``os.environ`` on its
    own, which is what makes credential resolution a plain function test rather
    than an exercise in patching a global.

    Args:
        argv: The arguments, without the program name.
        environ: The process environment, injected rather than read.

    Returns:
        The resolved options.
    """
    import argparse

    parser = argparse.ArgumentParser(prog="example-mcp-server", description="The example consumer of mcp-packaging")
    parser.add_argument("--transport", choices=tuple(kind.value for kind in TransportKind), default="stdio")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--credentials-file", default=None)
    parser.add_argument("--state", default=None)
    parsed = parser.parse_args(list(argv))
    return Options(
        transport=parsed.transport,
        host=parsed.host,
        port=parsed.port,
        credentials_file=parsed.credentials_file or environ.get(CREDENTIALS_DIRECTORY_VARIABLE) or "",
        state=parsed.state or environ.get(STATE_VARIABLE) or "",
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    read_file: Callable[[str], str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Wire, then probe, then serve.

    Args:
        argv: The arguments, without the program name. **None means "read the real
            command line"** - the case a console script actually is, and the one a
            suite that always passes ``argv`` never drives.
        read_file: The file-reading capability, injected.
        environ: The process environment, injected.

    Returns:
        The process exit status. Non-zero when a probe refused the start.
    """
    resolved = dict(os.environ) if environ is None else dict(environ)
    options = parse_arguments(list(sys.argv[1:] if argv is None else argv), resolved)
    credentials = _credentials(options, read_file or _read_text)
    secret = None if credentials is None else credentials.get(SHARED_SECRET_KEY)

    try:
        run_startup_probe(checks=_checks(options, secret))
    except StartupRefused:
        return EXIT_STARTUP_REFUSED

    server = _build_server()
    if not options.http_selected():
        serve_stdio(server)
        return EXIT_OK
    serve_http(
        server,
        host=options.host,
        port=options.port,
        verifier=lambda presented: verify_bearer_token(presented, secret or ""),
        ready_address=resolved.get(READY_NOTIFICATION_VARIABLE),
    )
    return EXIT_OK


def _checks(options: Options, secret: str | None) -> list[ProbeCheckFn]:
    """The probe, assembled from the layer's own constructors and nothing else.

    ⚠ THIS IS THE WHOLE OF WHAT `startup_probe` BEING DATA-DRIVEN BUYS. The
    reference consumer appends five checks of its own about a rotating credential;
    this one appends none, and the same runner serves both. A hardcoded probe
    would have made this consumer inherit five refusals about a document it does
    not have.

    Args:
        options: The resolved options.
        secret: The shared secret, or None when the credentials file had none.

    Returns:
        The checks, in the order they must run. Fail-fast, so the order is a
        decision rather than an accident.
    """
    state = Path(options.state)
    checks: list[ProbeCheckFn] = [
        private_directory_check(state),
        private_files_check(state),
    ]
    # The secret is checked only when a listener will actually open. A stdio
    # session's authentication boundary IS the operating system's process
    # boundary, so requiring a token there would refuse a start for nothing.
    if options.http_selected():
        checks.append(shared_secret_check(secret, MINIMUM_TOKEN_LENGTH))
    return checks


def _credentials(options: Options, read_file: Callable[[str], str]) -> Mapping[str, str] | None:
    """The secret, from the file and from NOWHERE else.

    A file that is not there yields None rather than a fallback. A fallback is the
    branch that turns "the file is missing" into "we quietly used something else",
    which is how a host ends up running on credentials nobody thinks it has.
    """
    path = options.credentials_file
    try:
        return credentials_file.parse(read_file(path))
    except OSError:
        emit_event(EventName.STARTUP_REFUSED, check=ProbeCheck.CREDENTIALS_FILE_ABSENT.value, detail=path)
        return None


def _build_server() -> McpServer:
    """Import the server object late, so the probe path never loads the SDK."""
    from example_mcp.server import build_server

    return build_server()


def _read_text(path: str) -> str:
    """Read a file. The one file-opening capability this package has."""
    return Path(path).read_text()
