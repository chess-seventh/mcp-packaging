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
import subprocess
import sys

import pytest

SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2] / "src" / "mcp_packaging"
NIX_ROOT = pathlib.Path(__file__).resolve().parents[2] / "nix"

#: The fleet's own words. A layer that learns one of these has learned a domain,
#: and the day it does is the day four consumers inherit the fifth's shape.
#:
#: ⚠ ONLY UNAMBIGUOUS IDENTIFIERS ARE ON THIS LIST, and the first version of it
#: is why. It also carried `measurement` and `oauth`, which are ordinary English
#: in a sentence EXPLAINING why a mechanism was left out - so the check fired on
#: the prose that documents the boundary rather than on prose that breaches it. A
#: rule whose true positives are outnumbered by its false ones gets an exemption
#: list, and an exemption list is where a real leak eventually hides.
#:
#: Every entry below is a name that can only appear here by mistake: the five
#: consumers ADR-001 names, and one consumer's API host, which is exactly what
#: `checks/deployment.nix` was found grepping the journal for.
FORBIDDEN_WORDS = (
    "the reference consumer",
    "the prior art",
    "a second consumer",
    "another consumer",
    "an-upstream-host",
    "another consumer",
    "a-domain-reading",
)

PYTHON_SOURCES = sorted(SOURCE_ROOT.rglob("*.py"))
NIX_SOURCES = sorted(NIX_ROOT.rglob("*.nix"))


@pytest.mark.boundary
@pytest.mark.parametrize("source", PYTHON_SOURCES, ids=lambda path: path.name)
def test_no_python_source_names_a_consumer_or_a_domain(source: pathlib.Path) -> None:
    """No module here may name a consumer of this layer, in code or in a comment.

    Comments included, deliberately. The prose is what a person reads to learn
    what a component is for, and prose that names one consumer teaches the next
    four that they are guests in somebody else's layer.
    """
    text = source.read_text().lower()
    found = [word for word in FORBIDDEN_WORDS if word in text]
    assert found == [], f"{source.name} names {found}, and this layer knows no domain"


@pytest.mark.boundary
@pytest.mark.parametrize("source", NIX_SOURCES, ids=lambda path: path.name)
def test_no_nix_source_names_a_consumer_or_a_domain(source: pathlib.Path) -> None:
    """The same rule for the Nix half, which is where the last real leak was.

    `checks/deployment.nix` asserted that the journal did not name `an-upstream-host` - one
    consumer's API host, hardcoded in a file whose own header said it named none.
    It passed review twice.
    """
    text = source.read_text().lower()
    found = [word for word in FORBIDDEN_WORDS if word in text]
    assert found == [], f"{source.name} names {found}, and this layer knows no domain"


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
