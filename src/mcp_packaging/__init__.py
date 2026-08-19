"""The shared packaging layer for the MCP server fleet.

It knows about MCP servers, sockets, headers, systemd units, Nix derivations and
filesystem modes. It knows nothing about any integration this fleet runs, nor
about the data one holds. **If a domain concept ever needs to enter it, that is
the signal the abstraction is wrong, not a reason to widen it.**

(The consumers are named in ADR-001, deliberately not here.)

That single rule (ADR-002) is what every module here is answerable to, and three
mechanisms hold it rather than review alone:

* nothing here names an environment variable - a consumer passes VALUES;
* the two open vocabularies, ``EventName`` and ``ProbeCheck``, carry only the
  members every consumer has, and each widens to ``| str`` so a consumer extends
  without this layer learning a domain word;
* ``tests/unit/test_boundary.py`` matches every published file against a SHAPE -
  any ``<something>-mcp`` that is not this repository's own; and, over every
  published file **except the two lock files**, any address and any port in the
  range these servers run in. A lock file is a machine-written record of where
  its dependencies came from, so it carries registry addresses by construction.

⚠ It does **not** catch a vendor name written on its own. It used to, through a
list of salted digests, and that list was reversible in under a minute - so the
rule published the roster it hid and was removed rather than dressed up. This
docstring described the deleted mechanism for a further two rounds, in the file
a reader opens first. ``README.md`` states what is and is not covered.

Importing this package pulls in no MCP server and no HTTP client. The two ``mcp``
imports in :mod:`mcp_packaging.transport` are function-local on purpose, so every
pure module here resolves with the SDK absent.
"""

from __future__ import annotations

#: The distribution version, so a consumer can pin what it built against.
__version__ = "0.1.0"
