# The MCP server package factory.
#
# THE SHARED LAYER ITSELF (ADR-002). Nothing in this file may name a consumer's
# fact - not a service, not an environment variable, not a port - and everything
# specific arrives as an argument. This file arrived here BY MOVE, unchanged,
# which is the whole of what the parameterised-first rule bought (ADR-001).
#
# What it builds: a closed Python environment resolved from the consumer's own
# `uv.lock`, with the console script asserted to route through the single
# declared entry point. The assertion is the point - a flake naming a command
# reads identically whether or not the build puts that command anywhere.
{
  pkgs,
  lib,
  pyproject-nix,
  uv2nix,
  pyproject-build-systems,

  # The consumer's repository root, holding pyproject.toml and uv.lock.
  workspaceRoot,

  # The distribution name in pyproject.toml, used to version the output.
  distributionName,

  # The single command the wheel installs, and the single module entry point
  # behind it. Exactly one of each (ADR-002): a wrapper invoking a module by
  # hand would be a second way in, and this build refuses to produce one.
  consoleScriptName,
  entryPoint,

  # 3.12 by default because uv.lock may resolve a dependency differently per
  # interpreter generation, so the generation the package is built against and
  # the one the suite runs against have to be written down and agree.
  pythonGeneration ? "3.12",

  # Prefer wheels: every dependency is then a resolved, prebuilt artefact rather
  # than something compiled out of an unpinned toolchain.
  sourcePreference ? "wheel",

  # Packages published as source distributions that call setuptools without
  # declaring it. Each entry supplies a MISSING BUILD SYSTEM and never changes a
  # version - that distinction is what keeps the lock file the only thing
  # deciding what lands in the closure.
  packagesNeedingSetuptools ? [ ],

  # WHICH distribution in the lock file this package closes over. Null means the
  # workspace's own default, which is the answer for a repository holding one
  # project - and it is what every consumer of this layer will pass.
  #
  # ⚠ IT EXISTS FOR THE ONE CASE THAT IS NOT THAT: a uv WORKSPACE, where the lock
  # holds several projects and "the default" is the root's rather than the
  # member's. This repository is exactly that case - `examples/example-mcp` is a
  # member - and without this argument the example would be built from the shared
  # layer's dependency set, which does not contain the example.
  #
  # A `uv2nix` dependency spec: an attribute set from distribution name to the
  # list of optional-dependency groups wanted, e.g. `{ example-mcp = [ ]; }`.
  dependencies ? null,

  meta,
}:
let
  entryPointModule = builtins.elemAt (lib.splitString ":" entryPoint) 0;
  entryPointFunction = builtins.elemAt (lib.splitString ":" entryPoint) 1;

  pythonAttributeName = "python${builtins.replaceStrings [ "." ] [ "" ] pythonGeneration}";
  python = pkgs.${pythonAttributeName};

  # Read as data, independently of uv2nix. ⚠ THIS COMMENT USED TO SAY "so a
  # parity check has an answer to compare against"; there is no parity check in
  # this repository and `docs/api.md` records that the ADR-promised one was not
  # built. What the read is FOR here is the derivation's name: the output is
  # versioned from the lock rather than from whatever uv2nix resolved, so the two
  # can be seen to disagree.
  lockFile = builtins.fromTOML (builtins.readFile (workspaceRoot + "/uv.lock"));

  versionOf =
    packageName:
    let
      candidates = builtins.filter (entry: entry.name == packageName) lockFile.package;
    in
    if builtins.length candidates == 1 then
      (builtins.head candidates).version
    else
      throw (
        "mkServerPackage: uv.lock does not resolve exactly one ${packageName} "
        + "(found ${toString (builtins.length candidates)})"
      );

  workspace = uv2nix.lib.workspace.loadWorkspace { inherit workspaceRoot; };
  lockedOverlay = workspace.mkPyprojectOverlay { inherit sourcePreference; };

  buildFixes =
    final: prev:
    builtins.listToAttrs (
      map (
        name:
        lib.nameValuePair name (
          prev.${name}.overrideAttrs (old: {
            nativeBuildInputs =
              (old.nativeBuildInputs or [ ]) ++ final.resolveBuildSystem { setuptools = [ ]; };
          })
        )
      ) packagesNeedingSetuptools
    );

  pythonSet = (pkgs.callPackage pyproject-nix.build.packages { inherit python; }).overrideScope (
    lib.composeManyExtensions [
      pyproject-build-systems.overlays.default
      lockedOverlay
      buildFixes
    ]
  );

  # A closed environment: every dependency resolved here, at build time, from
  # uv.lock. Nothing is installed or searched for while the server is answering
  # a question, and a dependency that cannot be resolved fails THIS derivation
  # naming itself rather than surfacing as an import error on the first call.
  serverEnvironment = pythonSet.mkVirtualEnv "${distributionName}-env" (
    if dependencies == null then workspace.deps.default else dependencies
  );
in
pkgs.runCommand "${distributionName}-${versionOf distributionName}"
  {
    inherit meta;
    passthru = { inherit serverEnvironment; };
  }
  ''
    set -euo pipefail

    installedCommand="${serverEnvironment}/bin/${consoleScriptName}"
    if [ ! -x "$installedCommand" ]; then
      echo "REFUSING TO BUILD: the package does not provide ${consoleScriptName}." >&2
      exit 1
    fi

    # ONE entry point, so the installed command and the packaged command cannot
    # name different things. The console script is generated from the
    # consumer's pyproject.toml declaration, so this compares what was actually
    # installed against what the flake says - and it refuses WHILE BUILDING,
    # rather than when somebody asks the running server a question.
    if ! grep -q "from ${entryPointModule} import ${entryPointFunction}" "$installedCommand"; then
      echo "REFUSING TO BUILD: ${consoleScriptName} does not route through ${entryPoint}." >&2
      echo "The packaged command and the declared console script have drifted." >&2
      exit 1
    fi

    ln -s "${serverEnvironment}" "$out"
  ''
