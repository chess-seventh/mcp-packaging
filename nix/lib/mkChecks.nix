# The check factory: one call, four checks, one `spec`.
#
# THE SHARED LAYER ITSELF (ADR-002 section 3). ⚠ THIS IS THE ONE PIECE OF THE
# SECTION-3 API THAT WAS NEVER BUILT. The reference consumer imported the four
# check files ONE BY ONE at its own call sites, so `lib.mkChecks` was an ADR
# promise with no code behind it - which is exactly the shape the must-prove
# "no ADR promising a factory the tree does not have" exists to catch.
#
# It matters more than tidiness. Importing four checks by hand means a consumer
# can import three, and the one it skips is invisible: there is no diff, no
# refusal, and a repository that ships four checks and runs three reports green.
# One call is the difference between choosing what to check and choosing what to
# name.
#
# ADR-002's draft signature listed about twenty arguments. It is one `spec` here
# instead, and that is the same decision section 3 already took for the other
# three factories: the fields are the fields of ONE record a consumer writes
# once, so a field added for a fourth consumer changes no call site.
{
  pkgs,
  lib ? pkgs.lib,

  # The consumer's own nixpkgs flake, for the closure search - which builds a
  # REAL system rather than a virtual machine, so it needs `nixosSystem` and not
  # a test driver.
  nixpkgs,
  system,

  # One record, read by every factory. See `docs/api.md` for the fields each
  # check reads and which of them may be omitted.
  spec,

  # The build output the checks run. Named by the consumer rather than defaulted,
  # so a repository cannot check one artefact and ship another.
  serverPackage,
}:
{
  # Readiness, bind exclusivity, state-area modes, restart policy, start-limit,
  # and the credentials refusal. A NixOS virtual-machine test.
  service = import ../checks/service.nix { inherit pkgs lib spec serverPackage; };

  # What only a whole machine can answer: a power cut, a port somebody else
  # holds, a store that will not take a write, and TWO of these services on one
  # box built from one factory and two specs. A virtual-machine test.
  deployment = import ../checks/deployment.nix { inherit pkgs lib spec serverPackage; };

  # The tightening set, read back off the RUNNING unit and compared whole. A
  # virtual-machine test.
  hardening = import ../checks/hardening.nix { inherit pkgs lib spec serverPackage; };

  # The headline gate: a real system closure, built with the service enabled and
  # its secrets supplied by file, then searched for every secret's value.
  #
  # ⚠ NOT a virtual-machine test, and that is deliberate rather than incidental.
  # Only BOOTING a machine needs KVM; building a system and searching it needs a
  # builder. The check that discharges the headline claim must not be the one
  # gated behind a capability half a fleet lacks.
  secret-search = import ../checks/secret-search.nix {
    inherit
      pkgs
      lib
      nixpkgs
      system
      spec
      serverPackage
      ;
  };
}
