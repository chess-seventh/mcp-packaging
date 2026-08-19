"""The example consumer of ``mcp-packaging``.

It integrates with nothing and holds exactly one secret. Both are the point: it
exists so the shared layer's API is exercised by a consumer with a DIFFERENT
credential shape from the reference implementation's, in this repository, on
every ``nix flake check``.
"""

from __future__ import annotations

__version__ = "0.1.0"
