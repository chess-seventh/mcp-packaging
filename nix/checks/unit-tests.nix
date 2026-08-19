# The Python half's own suite, run by `nix flake check`.
#
# ⚠ NEEDS NEITHER A VIRTUAL MACHINE NOR THE MCP SDK, and both absences are the
# point rather than a convenience. Every module in this layer resolves with the
# SDK missing - the two `mcp` imports in `transport` are function-local - so the
# suite runs against a bare interpreter, everywhere, in seconds. A layer whose
# unit tests needed a builder advertising virtualisation would have its cheapest
# feedback gated behind its most expensive capability.
#
# The suite is therefore also the strongest available assertion of the
# import-boundary claim: if a `mcp` or `httpx` import ever moved to module level,
# this check would fail to even collect.
{
  pkgs,
  lib,

  # The repository source. Passed in so the check reads what the flake reads.
  source,
}:
let
  interpreter = pkgs.python312.withPackages (packages: [ packages.pytest ]);
in
pkgs.runCommand "unit-tests"
  {
    nativeBuildInputs = [ interpreter ];
    meta.description = "The shared layer's own unit suite, on a bare interpreter with no SDK present";
  }
  ''
    cp -r ${source} source
    chmod -R u+w source
    cd source

    export PYTHONPATH="$PWD/src"
    export PYTHONDONTWRITEBYTECODE=1
    export HOME="$TMPDIR"

    python -m pytest tests/unit -q --no-header

    echo "unit suite passed on ${lib.getName interpreter}" > "$out"
  ''
