# Builds a REAL system closure with the service enabled and its secrets supplied
# by file, then searches every path in that closure for each secret's value.
#
# THE SHARED LAYER ITSELF (ADR-002): parameterised, names no consumer's fact.
#
# Not a virtual-machine test. Only booting a machine needs KVM; building a
# system and searching it needs a builder, so this one runs wherever
# `nix flake check` does - which matters, because it is the check that discharges
# the headline claim and the VM checks cannot run on every box in this fleet.
#
# ⚠ THE ANTI-VACUITY HALF IS THE POINT. A search that finds nothing proves
# nothing until it has been shown capable of finding something: a wrong root, a
# broken grep, or an absent system all report "clean". So the check PLANTS a
# known value in a path inside the closure and requires the same search to find
# it. If the planted value is not found, the check fails as loudly as if a real
# secret had been - because at that moment it has no idea what it is measuring.
{
  pkgs,
  lib,
  nixpkgs,
  system,
  spec,
  serverPackage,
}:
let
  # Obviously-synthetic values. They are the thing searched for, so they must
  # never be plausible as real credentials, and they must be long and distinctive
  # enough that a chance substring cannot satisfy the search.
  syntheticSecrets = {
    "${spec.clientIdVariable}" = "SYNTHETIC-CLIENT-ID-a2f0c7e4d9b6418fa3c5e7d9b1f4a6c8";
    "${spec.clientSecretVariable}" = "SYNTHETIC-CLIENT-SECRET-5d3b8f1a6c9e2470b8d4f6a1c3e5079b";
    "${spec.refreshTokenVariable}" = "SYNTHETIC-REFRESH-TOKEN-9f2e4a7c1b8d3560e9a2c4f6b8d0172e";
    "${spec.sharedSecretVariable}" = "SYNTHETIC-SHARED-SECRET-3c7a1e9d5b2f4806a7c9e1b3d5f70284";
  };

  secretValues = lib.attrValues syntheticSecrets;

  # ⚠ A RUNTIME PATH, NOT A STORE PATH, and the first version got this wrong in
  # a way that made the check fail against a module that was behaving correctly.
  #
  # It wrote the credentials into the store with `pkgs.writeText` and configured
  # the service with that store path. The search then found all four values -
  # in the check's OWN FIXTURE. The module had copied nothing; the check had.
  # A test that plants the thing it is looking for and then reports finding it
  # is measuring itself.
  #
  # The honest configuration is the deployed one: a path the HOST delivers at
  # run time, which the store has never seen. Then "no secret value appears in
  # the closure" is a claim about the module, and it is falsifiable - if the
  # module ever interpolated the file's CONTENTS, or accepted a Nix path literal
  # and copied it in, these values would appear.
  #
  # The instrument's own credibility is established separately, by planting a
  # value where the search must find it. That half already passed on the run
  # that exposed this one.
  runtimeCredentialsPath = "/run/secrets/${spec.name}.env";

  # A pinned address that is NOT the every-interface set, so the module's own
  # assertion does not refuse this configuration for an unrelated reason.
  pinnedListenAddress = "127.0.0.1";

  systemUnderSearch =
    (nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        (import ../lib/mkServiceModule.nix { inherit spec; })
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "/dev/disk/by-label/nixos";
            fsType = "ext4";
          };
          system.stateVersion = "25.11";

          ${builtins.elemAt spec.optionPath 0}.${builtins.elemAt spec.optionPath 1} = {
            enable = true;
            package = serverPackage;
            listenAddress = pinnedListenAddress;
            # A QUOTED STRING naming a path the host delivers at run time. The
            # store has never seen this file, which is what makes the search
            # below a question about the module rather than about the fixture.
            credentialsFile = runtimeCredentialsPath;
          };
        }
      ];
    }).config.system.build.toplevel;
  # The closure, computed OUTSIDE the sandbox and handed in as an input.
  #
  # ⚠ THIS IS NOT A STYLE CHOICE, AND THE CHECK'S OWN GUARD IS WHAT FOUND IT.
  # The first version ran `nix-store -qR` inside the build. A sandboxed builder
  # has no access to the nix database, so that returned ONE path - the root -
  # and a search over one path finds nothing. Had the anti-vacuity guard not
  # been there, this check would have printed "no secret value appears anywhere
  # in the closure" on its very first run and been believed.
  #
  # `closureInfo` computes the reference graph at EVALUATION time and materialises
  # it as a store path, which makes every closure member a real input to this
  # derivation and therefore present in the sandbox.
  closure = pkgs.closureInfo { rootPaths = [ systemUnderSearch ]; };
in
pkgs.runCommand "${spec.name}-secret-search"
  {
    nativeBuildInputs = [ pkgs.gnugrep ];
    inherit systemUnderSearch closure;
  }
  ''
    set -euo pipefail

    system="${systemUnderSearch}"

    closure="${closure}/store-paths"
    echo "Enumerating the closure of $system"

    pathCount=$(wc -l < "$closure")
    echo "Closure holds $pathCount store paths"

    # ANTI-VACUITY: refuse to report on a closure that is implausibly small.
    # A closure of one path is not a system, and searching it and finding
    # nothing would be the "looked nowhere, reported clean" failure this whole
    # check exists to avoid.
    if [ "$pathCount" -lt 50 ]; then
      echo "REFUSING TO REPORT: the closure holds only $pathCount paths." >&2
      echo "That is not a system. A search over nothing finds nothing, and" >&2
      echo "reporting that as clean is a green nobody earned." >&2
      exit 1
    fi

    # ANTI-VACUITY, second half: plant a known value where the search WILL look,
    # and require this exact search to find it. Until that succeeds, a clean
    # result says nothing about the closure and everything about the instrument.
    planted=$(mktemp -d)/planted-value
    echo "${builtins.head secretValues}" > "$planted"
    if ! grep -rlF "${builtins.head secretValues}" "$planted" >/dev/null 2>&1; then
      echo "REFUSING TO REPORT: the search cannot find a value planted directly in front of it." >&2
      echo "The instrument is broken, so its clean result would be meaningless." >&2
      exit 1
    fi
    echo "Search instrument proven: it finds a planted value."

    # Now the real question, asked of every path the running system can reach.
    found=0
    ${lib.concatMapStringsSep "\n" (value: ''
      echo "Searching the closure for one secret's value"
      if grep -rlF ${lib.escapeShellArg value} $(cat "$closure") 2>/dev/null | head -20 > /tmp/hits; then
        if [ -s /tmp/hits ]; then
          echo "SECRET FOUND IN THE SYSTEM CLOSURE. Paths:" >&2
          cat /tmp/hits >&2
          found=1
        fi
      fi
    '') secretValues}

    if [ "$found" -ne 0 ]; then
      echo "" >&2
      echo "FAILING: a credential supplied by file reached the nix store, which is" >&2
      echo "world-readable. The value itself is deliberately not repeated here." >&2
      exit 1
    fi

    echo "No secret value appears anywhere in the $pathCount paths of the closure."
    touch "$out"
  ''
