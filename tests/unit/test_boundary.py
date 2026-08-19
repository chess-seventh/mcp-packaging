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
import hashlib
import importlib
import pathlib
import re
import subprocess
import sys

import pytest

REPOSITORY = pathlib.Path(__file__).resolve().parents[2]


def _tracked() -> list[pathlib.Path]:
    """Every file git tracks, which is exactly what a push publishes.

    ⚠ NOT A GLOB OVER FOUR EXTENSIONS, and the first version was. It scanned
    `*.py`, `*.nix`, `*.toml` and `*.md`, so a name planted in `LICENSE`,
    `devenv.yaml`, `.gitignore` or either lock file went straight through while
    `README.md` claimed the mechanism covered "every published file". The set a
    push publishes is the set git tracks, so that is the set asked.
    """
    listing = subprocess.run(
        ["git", "-C", str(REPOSITORY), "ls-files", "-z"],
        capture_output=True,
        check=True,
    )
    return sorted(REPOSITORY / name for name in listing.stdout.decode().split("\0") if name)


def _readable(path: pathlib.Path) -> str:
    """A file's text, or empty for anything that is not text."""
    try:
        return path.read_text()
    except (UnicodeDecodeError, OSError):
        return ""


#: ⚠ THIS FILE IS SCANNED TOO, AND IT USED NOT TO BE. It excluded itself "so it
#: could write the patterns down" - and then wrote the forbidden names into its
#: own docstrings, explaining why they were forbidden. The one file whose job is
#: keeping operator facts out of a public repository was the only file still
#: publishing them, exempted by its own rule. Hashing every token is precisely
#: what makes the exemption unnecessary: nothing here has to spell one.
SCANNED = _tracked()

#: ⚠ EXCLUDED FROM THE ADDRESS RULES ONLY, never from the name rules. A lock file
#: is a machine-written record of where its own dependencies came from, so it is
#: full of registry addresses by construction and asking it about hosts is asking
#: the wrong question. A consumer's name cannot arrive in one by hand, and the
#: name rules still read them.
GENERATED = {"uv.lock", "flake.lock"}

ADDRESSABLE = [path for path in SCANNED if path.name not in GENERATED]

PYTHON_SOURCES = sorted((REPOSITORY / "src" / "mcp_packaging").rglob("*.py"))

#: This repository's own two distributions. Everything else matching the shape
#: below is another server, and another server is a domain.
OWN_NAMES = ("mcp-packaging", "mcp_packaging", "example-mcp", "example_mcp")

#: ⚠ A PATTERN, NOT A ROSTER, AND THE CHANGE IS ABOUT PUBLICATION. The first
#: version listed the fleet's servers by name - which put a private repository
#: roster into a PUBLIC repository, in the one file whose whole job is to keep
#: operator facts out of it. The pattern catches every server in the family
#: including ones that do not exist yet, and it names none of them.
#:
#: `IGNORECASE`, because the first pattern was `[a-z]`-only, so the same name
#: capitalised at the start of a sentence walked past it.
SIBLING_SERVER = re.compile(
    rf"\b(?!(?:{'|'.join(OWN_NAMES)})\b)[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*[-_]mcp\b",
    re.IGNORECASE,
)

#: ⚠ HASHED, BECAUSE A PATTERN CANNOT SEE A BARE VENDOR NAME AND A LIST CANNOT BE
#: PUBLISHED. A shape pattern catches `<something>-mcp`; it cannot catch the same
#: vendor written on its own, and written on its own is how the leak that started
#: all of this was written. So dropping the roster closed a publication hole and
#: opened a coverage one. Salted digests close both: the rule still fires on the
#: exact token, and a reader of this file learns that six words are forbidden and
#: cannot learn which.
#:
#: The refusal therefore cannot name the word. It names the FILE and the position,
#: which is enough: whoever just wrote it knows which word it was.
_SALT = "REDACTED-SALT"
FORBIDDEN_DIGESTS = frozenset(
    {
        "REDACTED-DIGEST-1",
        "REDACTED-DIGEST-2",
        "REDACTED-DIGEST-3",
        "REDACTED-DIGEST-4",
        "REDACTED-DIGEST-5",
        "REDACTED-DIGEST-6",
    }
)

#: Words split on this, lowercased, before hashing. Underscores are part of a
#: token rather than a separator, so a two-word domain noun spelled the way code
#: spells it is ONE token and can be hashed; split on it, each half would be an
#: ordinary English word no rule could forbid.
TOKEN = re.compile(r"[a-z0-9_]+")

#: A URL naming a LITERAL REMOTE HOST. Interpolated and loopback authorities are
#: allowed: those are the layer reaching a machine it was POINTED AT, which is the
#: job. A literal remote name can only be an upstream.
URL = re.compile(
    r"https?://(?!"
    r"\$|\{"
    r"|127\.0\.0\.1|localhost|\[::1\]"
    r"|github\.com|pypi\.org|python\.org|nixos\.org"
    r")[^\s\)\"'`]+"
)

#: ⚠ A HOST WITHOUT A SCHEME, WHICH IS THE SHAPE OF THE LAST REAL LEAK. The check
#: that was found grepping a journal for one consumer's API host wrote it bare -
#: no `https://` in front of it - so a rule keyed on a scheme would have missed
#: the very thing it was written for.
BARE_HOST = re.compile(
    r"\b(?!github\.com|pypi\.org|python\.org|nixos\.org)"
    r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:net|com|io|org|internal|local|lan)\b",
    re.IGNORECASE,
)

#: A port in the range these servers are deployed in. The example's own is the one
#: number this repository may write; anything else in the range is an allocation,
#: and an allocation is an operator's.
FLEET_PORT = re.compile(r"(?<![\d.])8[0-9]{3}(?![\d.])")
OWN_PORT = "8799"


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
    found = sorted({match.lower() for match in SIBLING_SERVER.findall(_readable(source))})
    assert found == [], f"{_relative(source)} names {found}, and this layer knows no other server"


@pytest.mark.boundary
@pytest.mark.parametrize("source", SCANNED, ids=_relative)
def test_no_published_file_writes_a_forbidden_token(source: pathlib.Path) -> None:
    """The bare vendor names a shape-based pattern cannot see.

    ⚠ THIS IS THE HALF THAT DROPPING THE ROSTER LOST. A pattern catches
    `<name>-mcp`; it cannot catch the same vendor written on its own, which is how
    the last real leak was written. Digests restore the coverage without restoring
    the disclosure.

    The refusal names the file and the token's position and NOT the token. That is
    the whole point of hashing it, and it costs nothing in practice: whoever just
    wrote the word can see which one it is.
    """
    text = _readable(source).lower()
    offences = [
        match.start()
        for match in TOKEN.finditer(text)
        if hashlib.sha256((_SALT + match.group()).encode()).hexdigest()[:32] in FORBIDDEN_DIGESTS
    ]
    assert offences == [], (
        f"{_relative(source)} writes a forbidden token at offset(s) {offences[:5]}. "
        "It is a name this layer may not know; the message does not repeat it, because this "
        "repository is public and the refusal would publish the very thing it refuses."
    )


@pytest.mark.boundary
@pytest.mark.parametrize("source", ADDRESSABLE, ids=_relative)
def test_no_published_file_names_an_upstream(source: pathlib.Path) -> None:
    """No address of a machine outside this repository, with or without a scheme.

    ⚠ THE LAST REAL LEAK OUT OF THE EXTRACTION WAS A BARE HOST: a check asserted
    that a journal did not name one consumer's API host, written with no scheme in
    front of it, in a file whose own header said it named none. It passed review
    twice. A rule keyed on `https://` would have missed it, so there are two.
    """
    text = _readable(source)
    found = sorted({*URL.findall(text), *BARE_HOST.findall(text)})
    assert found == [], f"{_relative(source)} names {found}, and this layer reaches nothing"


@pytest.mark.boundary
@pytest.mark.parametrize("source", ADDRESSABLE, ids=_relative)
def test_no_published_file_writes_a_port_allocation(source: pathlib.Path) -> None:
    """A port in the range these servers run in is an operator's allocation.

    The example's own is the one number this repository may write. The rule exists
    because the same fact was scrubbed from a module comment and left standing in
    a reference document two commits later — the scrub was by hand, so it missed.
    """
    found = sorted({port for port in FLEET_PORT.findall(_readable(source)) if port != OWN_PORT})
    assert found == [], f"{_relative(source)} writes {found}, and a port allocation is an operator's"


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
