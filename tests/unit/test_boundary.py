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
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

REPOSITORY = pathlib.Path(__file__).resolve().parents[2]


#: Files this repository ignores rather than publishes. ⚠ A HAND-WRITTEN LIST,
#: and `test_the_scanned_set_is_exactly_what_git_publishes` is what keeps it
#: honest - it caught this very list missing three entries on its first run.
UNPUBLISHED_FILES = {".git", "devenv.lock", ".pre-commit-config.yaml"}

#: Directories that are build output, interpreter output or shell state rather
#: than source. ⚠ NAMED, RATHER THAN "ANYTHING STARTING WITH A DOT". The dot rule
#: was shorter and it made `.github/` invisible to the gate - a workflow file
#: naming an upstream would have passed `nix flake check` and been caught only by
#: a dev-shell run somebody remembered to do. The enforcing gate must not be the
#: blind one.
UNPUBLISHED_DIRS = {
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    ".git",
    ".devenv",
    ".direnv",
    ".venv",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".nwave",
}


def _published() -> list[pathlib.Path]:
    """Every file this repository publishes, by walking it.

    ⚠ NOT `git ls-files`, AND THE REASON IS THE NIX SANDBOX. The unit check runs
    inside a build with no `git` binary and no `.git` directory - the source is a
    copied store path - so a mechanism that shelled out to git collected nothing
    there and failed at import. A boundary rule that cannot run in the gate is a
    boundary rule that runs only where somebody remembers to run it.

    ⚠ THE EXCLUSIONS APPLY IN A CHECKOUT AND NOWHERE ELSE, and that asymmetry is
    the fix rather than a shortcut. A hand-written exclusion list is a blind spot,
    and the gate must not be the thing that is blind - a reviewer walked six
    planted files past `nix flake check` through this list alone. But the Nix
    source IS already the published set: the flake copies what git tracks, so
    caches, build output and ignored files are not there to be excluded. So where
    there is no `.git` the walk takes everything it finds and the blind spot does
    not exist; where there is one, the exclusions apply and
    `test_the_scanned_set_is_exactly_what_git_publishes` cross-checks them.

    Symlinks are INCLUDED. Their contents are their target's and may be nothing,
    but their NAMES are published like any other, and a name is enough.

    Excluded directories are NAMED rather than matched on a leading dot, so a
    tracked `.github/` is scanned. `.git` is on BOTH lists: in a linked git
    worktree it is a file, so a directory rule alone would read it.
    """
    checkout = (REPOSITORY / ".git").exists()
    return sorted(
        path
        for path in REPOSITORY.rglob("*")
        # ⚠ `is_dir()` FOLLOWS THE LINK, so a symlink pointing at a directory was
        # dropped from the walk entirely - neither its target string nor its own
        # path rule-checked - while the docstring below claimed symlinks are
        # included. A link is never a directory for this purpose: git stores it as
        # its target string either way.
        if not (path.is_dir() and not path.is_symlink())
        and (
            not checkout
            or (
                not any(
                    part in UNPUBLISHED_DIRS or part.endswith(".egg-info")
                    for part in path.relative_to(REPOSITORY).parts[:-1]
                )
                and path.name not in UNPUBLISHED_FILES
                and not path.name.startswith("result")
            )
        )
    )


def _readable(path: pathlib.Path) -> str:
    """A file's bytes as text, whatever those bytes are.

    ⚠ IT USED TO RETURN THE EMPTY STRING FOR ANYTHING THAT WOULD NOT DECODE, and
    that is a rule lying about itself: a tracked file with one high byte in it - a
    PNG, a PDF, a latin-1 note - was scanned, read as nothing, and passed every
    rule while the README claimed the mechanism covered every published file. A
    planted `docs/blob.dat` carrying a server name, a host and a port went through
    the gate AND the development shell.

    latin-1 maps all 256 byte values, so it cannot raise. The result is nonsense
    for a real binary and that is fine: the rules look for ASCII names and
    addresses, and those survive the mapping byte for byte.
    """
    if path.is_symlink():
        # ⚠ THE TARGET STRING IS THE PUBLISHED BLOB. Git stores a symlink as its
        # target and a forge renders it, so the target is text this repository
        # publishes. `read_bytes` FOLLOWS the link instead: for a target outside
        # the tree it raised, the handler below returned the empty string, and a
        # name, a host and a port inside the target went through the whole gate.
        # This history has already tracked a dangling symlink once.
        return os.readlink(path)
    try:
        return path.read_bytes().decode("latin-1")
    except OSError:
        return ""


#: Everything this repository publishes. ⚠ THIS FILE IS IN THE SET TOO, and it
#: used not to be: it excluded itself "so it could write the patterns down", and
#: then wrote the forbidden names into its own docstrings. The one file whose job
#: is keeping operator facts out of a public repository was the only one still
#: publishing them, exempted by its own rule.
SCANNED = _published()

#: ⚠ EXEMPT FROM THE ADDRESS RULES ONLY, never from the name rules. A lock file is
#: a machine-written record of where its own dependencies came from, so it is full
#: of registry addresses by construction and asking it about hosts is asking the
#: wrong question. A server's name cannot arrive in one by hand, and the name
#: rules still read them.
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

# ⚠ THERE IS NO BARE-VENDOR-NAME RULE HERE, AND ITS ABSENCE IS A DECISION THAT
# COST THREE ATTEMPTS. To catch a vendor written on its own, a rule has to know
# the word; and any representation of "this exact word is forbidden" that lives
# in a PUBLIC tree can be read back. A plaintext list obviously. A salted SHA-256
# was tried and is no better: the salt sits beside it, the words are short and
# ordinary, and a reviewer recovered all six from a hand-typed candidate list in
# under a minute, with no wordlist and no GPU. A comment claiming a reader
# "cannot learn which" was simply false, and a false claim about a disclosure is
# worse than the disclosure.
#
# So this file enforces the rules that publish NOTHING - a shape, an address, a
# port, a filename - and the bare name is caught upstream of publication instead:
# by the redaction pass that rewrites this branch before its first push, and by
# review. `README.md` says so rather than implying coverage that is not here.

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
#: ⚠ THE FIRST VERSION KNEW SEVEN TOP-LEVEL DOMAINS, WHICH IS THE WRONG SEVEN.
#: A host under `.ch`, `.dev`, `.cloud` or any country code walked past a rule
#: written to catch upstreams. The list is long now and still finite - a filename
#: is shaped exactly like a host, so a rule matching ANY dotted name would fire on
#: `pyproject.toml`. What it therefore cannot cover is stated in the README - and
#: this comment claimed that before the README said it, which is the kind of claim
#: about another document that nobody checks.
BARE_HOST = re.compile(
    r"\b(?!github\.com|pypi\.org|python\.org|nixos\.org)"
    r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*"
    r"\.(?:net|com|io|org|internal|local|lan|dev|app|cloud|ai|xyz|site|online"
    r"|ch|de|fr|uk|eu|us|es|it|nl|be|at|se|no|dk|fi|pl|pt|ie|cz)\b",
    re.IGNORECASE,
)

#: ⚠ IPv6 HAS ITS OWN RULE BECAUSE THE FLEET THIS SERVES IS REACHED OVER IT, and
#: the FIRST version of that rule matched only fully-expanded addresses - which is
#: to say none, because `::` compression is how every address is actually written.
#: A compressed unique-local address passed; only the eight-group spelling was
#: caught. The comment above it claimed it "would miss every unique-local and
#: every link-local address" if it knew only dotted quads, and it missed them
#: anyway - the rule that names a shape must not be written with one in it.
#:
#: Three branches: compressed with a head, compressed without one, and expanded.
#: The expanded branch demands at least three groups so that a clock time - `12:30`
#: - is not an address.
IPV6_ADDRESS = re.compile(
    r"(?<![0-9a-z:])"
    r"(?:"
    r"[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?"
    r"|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?"
    r"|(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}"
    r")"
    r"(?![0-9a-z:])",
    re.IGNORECASE,
)

#: This layer's own address vocabulary: loopback, the unspecified address, and
#: every spelling of "every interface" that the module refuses BY NAME. A rule
#: that flagged those would flag the guard that exists to refuse them.
IPV6_ALLOWED = {"::", "::0", "::1", "0:0:0:0:0:0:0:0", "::ffff:0", "::ffff:0.0.0.0"}


def _addresses_in(text: str) -> set[str]:
    """The IPv6 addresses in some text, without the things that merely look like one.

    ⚠ A RULE THAT CRIES WOLF GETS SWITCHED OFF, so the expanded branch is filtered
    rather than left to fire on a wall-clock time (`10:30:45`), a MAC address, or
    a slice written with colons. None of those exists in this tree today, and that
    is exactly when a false positive is cheapest to remove.

    Two filters, both structural rather than a list of exceptions:

    * a compressed address contains `::` and nothing else does, so it is kept
      unconditionally;
    * an expanded one must carry a hex LETTER somewhere - a purely decimal
      colon-separated string is a time or a version, not an address anyone
      writes - and must not be six groups of exactly two digits, which is a MAC.
    """
    found = set()
    for candidate in IPV6_ADDRESS.findall(text):
        if candidate.lower() in IPV6_ALLOWED:
            continue
        if "::" in candidate:
            found.add(candidate)
            continue
        groups = candidate.split(":")
        if not any(character in "abcdefABCDEF" for character in candidate):
            continue
        if len(groups) == 6 and all(len(group) == 2 for group in groups):
            continue
        found.add(candidate)
    return found


#: An address with no name at all. `BARE_HOST` cannot see one, and a fleet is
#: reached by address at least as often as by name.
#:
#: Three ranges are this layer's own vocabulary and are allowed: the whole of
#: loopback (the checks bind a SECOND loopback address on purpose, to tell "the
#: operator chose this" from "the default is loopback"), the every-interface
#: value the module refuses by name, and TEST-NET-1 - the block IETF reserved so
#: that a documentation address cannot be mistaken for somebody's real one.
IP_ADDRESS = re.compile(r"(?<![\d.])(?!127\.|192\.0\.2\.)(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _quads_in(text: str) -> set[str]:
    """The IPv4 addresses in some text, minus this layer's own vocabulary.

    The unspecified address is filtered STRUCTURALLY - every octet is zero -
    rather than by listing `0.0.0.0`. The module names it in four spellings now,
    and a list would have to grow with them; "all the octets are zero" does not.
    """
    return {candidate for candidate in IP_ADDRESS.findall(text) if any(int(octet) for octet in candidate.split("."))}


#: A port in the range these servers are deployed in. The example's own is the one
#: number this repository may write; anything else in the range is an allocation,
#: and an allocation is an operator's.
#:
#: ⚠ THE LOOKAHEAD EXCLUDED A FULL STOP AND THAT KILLED THE RULE. A port at the
#: end of a sentence passed while the same port mid-sentence failed - and the
#: leak this rule was added to stop recurring was a sentence in a reference
#: document, which is to say prose, which is to say it ended in a full stop.
FLEET_PORT = re.compile(r"(?<![\d.])8[0-9]{3}(?!\d)")
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
@pytest.mark.parametrize("source", ADDRESSABLE, ids=_relative)
def test_no_published_file_names_an_upstream(source: pathlib.Path) -> None:
    """No address of a machine outside this repository, with or without a scheme.

    ⚠ THE LAST REAL LEAK OUT OF THE EXTRACTION WAS A BARE HOST: a check asserted
    that a journal did not name one consumer's API host, written with no scheme in
    front of it, in a file whose own header said it named none. It passed review
    twice. A rule keyed on `https://` would have missed it, so there are two.
    """
    text = _readable(source)
    found = sorted(
        {
            *URL.findall(text),
            *BARE_HOST.findall(text),
            *_quads_in(text),
            *_addresses_in(text),
        }
    )
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


@pytest.mark.boundary
def test_the_scanned_set_is_exactly_what_git_publishes() -> None:
    """The walk above and `git ls-files` must agree.

    ⚠ THE WALK IS THE MECHANISM AND THIS IS THE CHECK ON IT. The walk has to be
    the mechanism, because the gate runs it where git does not exist. But a walk
    with a hand-written exclusion list drifts from what a push actually sends the
    moment somebody adds a build directory, and the drift is invisible: files
    simply stop being scanned and everything still passes.

    So wherever git IS available - the development shell, a pre-commit hook - the
    two are compared and a difference is a failure. Where it is not, this one test
    reports why it could not ask, and every other rule in the file still runs
    against the walk.
    """
    if not (REPOSITORY / ".git").exists() or shutil.which("git") is None:
        pytest.skip("no git here (the Nix sandbox); the walk is unchecked in this environment")

    listing = subprocess.run(
        ["git", "-C", str(REPOSITORY), "ls-files", "-z"],
        capture_output=True,
        check=True,
    )
    tracked = {REPOSITORY / name for name in listing.stdout.decode().split("\0") if name}
    walked = set(SCANNED)

    assert walked - tracked == set(), f"the walk scans files git does not publish: {sorted(walked - tracked)}"
    assert tracked - walked == set(), f"git publishes files the walk does not scan: {sorted(tracked - walked)}"


@pytest.mark.boundary
def test_no_published_path_carries_anything_the_rules_forbid() -> None:
    """A NAME, not only a body, and EVERY rule rather than two of them.

    ⚠ `docs/<vendor>-notes.md` with an entirely innocuous body passed every
    content rule, and a public repository publishes its file listing on its
    landing page - the path is the first thing a visitor reads and it was the one
    thing unchecked. The first version of this test then applied only the server
    and hostname rules, so a filename built out of an address and a port still
    passed. A path is text; it gets the same rules the text inside gets.
    """
    offences = sorted(
        _relative(path)
        for path in SCANNED
        if SIBLING_SERVER.search(_relative(path))
        or BARE_HOST.search(_relative(path))
        or _quads_in(_relative(path))
        or _addresses_in(_relative(path))
        or [port for port in FLEET_PORT.findall(_relative(path)) if port != OWN_PORT]
    )
    assert offences == [], f"these paths carry something this layer may not know: {offences}"
