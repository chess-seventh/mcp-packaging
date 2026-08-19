"""The shared packaging layer for the MCP server fleet.

It knows about MCP servers, sockets, headers, systemd units, Nix derivations and
filesystem modes. It knows nothing about The reference consumer, The prior art, Bring, ICS, Another consumer,
OAuth grants, measurements, or health data. **If a domain concept ever needs to
enter it, that is the signal the abstraction is wrong, not a reason to widen it.**

That single rule (ADR-002) is what every module here is answerable to, and three
mechanisms hold it rather than review alone:

* nothing here names an environment variable - a consumer passes VALUES;
* the two open vocabularies, ``EventName`` and ``ProbeCheck``, carry only the
  members every consumer has, and each widens to ``| str`` so a consumer extends
  without this layer learning a domain word;
* ``tests/unit/test_boundary.py`` walks these sources for the fleet's own words
  and fails on one.

Importing this package pulls in no MCP server and no HTTP client. The two ``mcp``
imports in :mod:`mcp_packaging.transport` are function-local on purpose, so every
pure module here resolves with the SDK absent.
"""

from __future__ import annotations

#: The distribution version, so a consumer can pin what it built against.
__version__ = "0.1.0"
