# The build-system escape hatch is general, and stays general.
#
# ⚠ THIS CHECK EXISTS BECAUSE THE HATCH WAS HARDCODED AND NOTHING SAID SO. Its
# predecessor took a list of package names and applied the literal
# `resolveBuildSystem { setuptools = [ ]; }` to every one of them. That was
# invisible: no call site in this repository passed the argument, no check
# exercised it, and the example consumer never needed it - so the one mechanism
# for "this package's build backend is not resolvable" worked for exactly one
# build backend, and the first external consumer to need a different one found
# out by reading a `ModuleNotFoundError` (L185).
#
# So the assertion below is deliberately about a build system that is NEITHER
# `setuptools` NOR `hatchling`: proving the hatch with the case that motivated it
# would prove only that the new default is the new right answer, which is the
# same mistake one step along.
#
# It applies the overlay to a STUB package set and reads back what reached
# `resolveBuildSystem`, so it needs no interpreter, no lock file, no network and
# no builder feature - an evaluation and a `touch`. A proof that requires
# building the thing it is proving is a proof nobody runs.
{
  pkgs,
  lib,
}:
let
  # A build system this repository does not use and does not default to. If the
  # hatch is ever narrowed back to a fixed set, this is the line that fails.
  neitherSetuptoolsNorHatchling = {
    flit-core = [ ];
  };

  # A recording stand-in for the python package set. `resolveBuildSystem` is the
  # only function the overlay reaches for, and here it returns a value CARRYING
  # the spec it was handed - so what the overlay passed through is read off the
  # result rather than inferred from a build that happened to succeed.
  recordingFinal = {
    resolveBuildSystem = spec: [ { resolvedFrom = spec; } ];
  };

  # The smallest thing that answers `overrideAttrs`. Real packages carry a great
  # deal more; none of it is what this check is about.
  stubPackage = attrs: attrs // { overrideAttrs = f: stubPackage (attrs // f attrs); };

  prev = {
    needs-a-backend = stubPackage { nativeBuildInputs = [ "already-here" ]; };
    ordinary-package = stubPackage { nativeBuildInputs = [ ]; };
  };

  applied = import ../lib/buildFixes.nix {
    packagesNeedingBuildSystems = {
      needs-a-backend = neitherSetuptoolsNorHatchling;
    };
  } recordingFinal prev;

  emptyApplied = import ../lib/buildFixes.nix {
    packagesNeedingBuildSystems = { };
  } recordingFinal prev;

  fixedInputs = applied.needs-a-backend.nativeBuildInputs;

  claims = [
    {
      name = "it touches only the packages it was asked about";
      holds = builtins.attrNames applied == [ "needs-a-backend" ];
      saw = builtins.toString (builtins.attrNames applied);
    }
    {
      name = "an empty request is an empty overlay, not a global fix";
      holds = emptyApplied == { };
      saw = builtins.toString (builtins.attrNames emptyApplied);
    }
    {
      name = "the package's own build inputs survive, and the fix is appended";
      holds = builtins.elemAt fixedInputs 0 == "already-here";
      saw = builtins.toString (builtins.length fixedInputs);
    }
    {
      # THE CLAIM THE WHOLE FILE IS FOR. Not "a build system arrived" - the
      # caller's OWN spec arrived, unread and unrewritten.
      name = "the caller's spec reaches resolveBuildSystem verbatim";
      holds = (builtins.elemAt fixedInputs 1).resolvedFrom == neitherSetuptoolsNorHatchling;
      saw = builtins.toString (builtins.attrNames (builtins.elemAt fixedInputs 1).resolvedFrom);
    }
  ];

  broken = builtins.filter (claim: !claim.holds) claims;
in
if broken != [ ] then
  throw (
    "build-system-hook: the escape hatch is no longer general.\n"
    + lib.concatMapStringsSep "\n" (claim: "  FAILED: ${claim.name} (saw: ${claim.saw})") broken
  )
else
  pkgs.runCommand "build-system-hook-check" { } ''
    touch "$out"
  ''
