"""The boundary rule, as a mechanism rather than a paragraph.

ADR-002's rule is the only rule this layer has: it knows about MCP servers,
sockets, headers, systemd units, Nix derivations and filesystem modes, and it
knows nothing about any integration. A rule without a mechanism is a wish, and
this file is the mechanism for the two halves a reviewer is worst at: a domain
word arriving in a comment nobody re-reads, and a dependency arriving in a
closure nobody opens.
"""

from __future__ import annotations

import ast
import importlib
import pathlib
import re
import subprocess
import sys

import pytest

REPOSITORY = pathlib.Path(__file__).resolve().parents[2]

#: Everything this repository PUBLISHES. ⚠ THE SET USED TO BE `src/` AND `nix/`
#: ALONE, and a planted leak in `flake.nix` passed all 28 tests - while
#: `examples/` breached the rule at the time it was written. A boundary mechanism
#: that does not cover the files a reader opens first is a mechanism with a hole
#: in exactly the place prose gets written.
#:
#: `tests/` is excluded because this file must be able to write the patterns down
#: in order to search for them.
SCANNED = sorted(
    path
    for pattern in ("*.py", "*.nix", "*.toml", "*.md")
    for path in REPOSITORY.rglob(pattern)
    if "/tests/" not in f"/{path.relative_to(REPOSITORY)}" and not path.relative_to(REPOSITORY).parts[0].startswith(".")
)

PYTHON_SOURCES = sorted((REPOSITORY / "src" / "mcp_packaging").rglob("*.py"))

#: This repository's own two distributions. Everything else matching the shape
#: below is another server, and another server is a domain.
OWN_NAMES = ("mcp-packaging", "mcp_packaging", "example-mcp", "example_mcp")

#: ⚠ A PATTERN, NOT A ROSTER, AND THE CHANGE IS ABOUT PUBLICATION. The first
#: version listed the fleet's servers by name - which put a private repository
#: roster into a PUBLIC repository, in the one file whose whole job is to keep
#: operator facts out of it. The pattern catches every server in the family
#: including ones that do not exist yet, and it names none of them.
SIBLING_SERVER = re.compile(rf"\b(?!(?:{'|'.join(OWN_NAMES)})\b)[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*[-_]mcp\b")

#: This layer opens no outbound connection and integrates with nothing, so a URL
#: naming a LITERAL REMOTE HOST in its published sources is either an upstream it
#: must not know or dead prose.
#:
#: ⚠ THREE AUTHORITIES ARE ALLOWED, AND THE FIRST TWO ARE WHY THIS IS A REGEX
#: RATHER THAN A GREP FOR "http". The checks build addresses out of the
#: consumer's own spec (`http://${...}`) and the session probe out of its shell
#: arguments (`http://$host:$port`) - those are the layer reaching a machine it
#: was POINTED AT, which is the whole job. Loopback is allowed for the same
#: reason. A literal remote name is the thing that can only be an upstream.
URL = re.compile(
    r"https?://(?!"
    r"\$|\{"  # an interpolation: an address the caller supplied
    r"|127\.0\.0\.1|localhost|\[::1\]"  # this machine
    r"|github\.com/chess-seventh/mcp-packaging"  # this repository's own forge
    r")[^\s\)\"'`]+"
)

#: A domain noun no packaging layer has a reason to spell.
FORBIDDEN_WORDS = ("a-domain-reading",)


def _relative(path: pathlib.Path) -> str:
    return str(path.relative_to(REPOSITORY))


@pytest.mark.boundary
@pytest.mark.parametrize("source", SCANNED, ids=_relative)
def test_no_published_file_names_another_server(source: pathlib.Path) -> None:
    """Nothing this repository publishes may name another server in the family.

    Comments and prose included, deliberately. The prose is what a person reads to
    learn what a component is for, and prose that names one consumer teaches the
    next four that they are guests in somebody else's layer — and in a PUBLIC
    repository it also publishes which private servers exist.

    Matched by SHAPE rather than against a list, so the rule holds for a consumer
    nobody has written yet and this file publishes no roster of its own.
    """
    found = sorted(set(SIBLING_SERVER.findall(source.read_text())))
    assert found == [], f"{_relative(source)} names {found}, and this layer knows no other server"


@pytest.mark.boundary
@pytest.mark.parametrize("source", SCANNED, ids=_relative)
def test_no_published_file_names_an_upstream(source: pathlib.Path) -> None:
    """No URL outside this repository's own forge.

    ⚠ THE LAST REAL LEAK OUT OF THE EXTRACTION WAS EXACTLY THIS SHAPE: a check
    asserted that the journal did not name one consumer's API host, hardcoded in a
    file whose own header said it named none. It passed review twice. That address
    is now a parameter the consumer supplies, and this is what keeps it one.
    """
    found = sorted(set(URL.findall(source.read_text())))
    assert found == [], f"{_relative(source)} names {found}, and this layer reaches nothing"


@pytest.mark.boundary
@pytest.mark.parametrize("source", SCANNED, ids=_relative)
def test_no_published_file_names_a_domain_noun(source: pathlib.Path) -> None:
    """The few words that can only appear here by mistake."""
    text = source.read_text().lower()
    found = [word for word in FORBIDDEN_WORDS if word in text]
    assert found == [], f"{_relative(source)} names {found}, and this layer knows no domain"


@pytest.mark.boundary
def test_importing_the_layer_pulls_in_no_mcp_server_and_no_http_client() -> None:
    """`import mcp_packaging` must not drag a server or an HTTP client in.

    ⚠ ASKED IN A FRESH INTERPRETER, NOT IN THIS ONE. The test session has already
    imported half the world, so `sys.modules` here answers a question about the
    suite rather than about the package. A subprocess is the only honest way to
    ask what ONE import costs.

    This is the must-prove "the Python half is importable without pulling in any
    single integration's server", turned into a mechanism. It holds because both
    `mcp` imports in `transport` are function-local, and it is exactly the kind of
    property a tidy-up moves to the top of the file and silently breaks.
    """
    programme = (
        "import sys\n"
        "import mcp_packaging\n"
        "import mcp_packaging.transport\n"
        "import mcp_packaging.bearer\n"
        "import mcp_packaging.startup_probe\n"
        "import mcp_packaging.credentials_file\n"
        "import mcp_packaging.store_modes\n"
        "import mcp_packaging.events\n"
        "leaked = sorted(n for n in sys.modules if n.split('.')[0] in {'mcp', 'httpx', 'uvicorn', 'anyio'})\n"
        "print(','.join(leaked))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", programme],
        capture_output=True,
        text=True,
        check=True,
    )
    leaked = [name for name in result.stdout.strip().split(",") if name]
    assert leaked == [], f"importing the layer pulled in {leaked}"


@pytest.mark.boundary
@pytest.mark.parametrize("source", PYTHON_SOURCES, ids=lambda path: path.name)
def test_no_module_reads_an_environment_variable(source: pathlib.Path) -> None:
    """This layer names no environment variable, so it reads none.

    A consumer's composition root is the only place that may. The rule is worth a
    mechanism because reading one is a single convenient line, and the convenience
    is precisely what makes it the likeliest breach.
    """
    tree = ast.parse(source.read_text())
    reads = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr in {"environ", "getenv"}]
    assert reads == [], f"{source.name} reads the environment; only a consumer's composition root may"


@pytest.mark.boundary
def test_every_module_the_package_ships_is_importable() -> None:
    """A module that cannot be imported is a module no other test here covers."""
    for source in PYTHON_SOURCES:
        importlib.import_module(f"mcp_packaging.{source.stem}" if source.stem != "__init__" else "mcp_packaging")
