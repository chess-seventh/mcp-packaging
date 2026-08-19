# The exported API is named, and every symbol in it exists.
#
# ⚠ THIS CHECK EXISTS BECAUSE THE ADR DID NOT MATCH THE TREE, and nothing said
# so. ADR-002 section 3 specifies `lib.mkChecks`, section 2 specifies
# `lib/hardening.nix` and `lib/ports.nix` - and in the reference implementation
# the first was never built as a factory at all, the second existed only as an
# inline table, and the third was later REJECTED by ADR-007 section 2 without
# section 2 being amended. Three promises, one of them retracted somewhere else,
# and the only way to find out was to read the tree.
#
# A repository whose published API is a paragraph has an API that drifts. This
# check makes the surface a LIST that fails the build when it stops being true,
# which is the difference between documenting an interface and having one.
#
# It needs no builder feature at all - it is an evaluation plus a `touch` - so it
# runs everywhere, which matters on a fleet where half the boxes cannot run a
# virtual-machine test.
{
  pkgs,
  lib,

  # The flake's own `lib` output. Passed in rather than imported, so what is
  # checked is what a CONSUMER would get and not what this file can reach.
  api,
}:
let
  # THE PUBLISHED SURFACE. A change here is a breaking change for every consumer
  # repository, and it should be as visible in a diff as the code it names.
  factories = [
    "mkServerPackage"
    "mkServiceModule"
    "mkSessionProbe"
    "mkChecks"
    "mkFixtures"
  ];

  data = [
    "hardening"
  ];

  promised = factories ++ data;
  exported = builtins.attrNames api;

  without = names: from: builtins.filter (name: !(builtins.elem name from)) names;

  missing = without promised exported;
  undocumented = without exported promised;

  notAFunction = builtins.filter (name: !(builtins.isFunction api.${name})) factories;
  notAnAttrset = builtins.filter (name: !(builtins.isAttrs api.${name})) data;

  # The hardening data is the one export a consumer reads FIELDS off, so its
  # shape is part of the surface rather than an implementation detail.
  hardeningFields = [
    "serviceConfig"
    "posture"
  ];
  hardeningMissing = without hardeningFields (builtins.attrNames api.hardening);
in
assert
  missing == [ ]
  || throw ''
    REFUSING TO EVALUATE: the published API names ${builtins.toString missing}, and the flake does not
    export it. A promise with no code behind it is the defect this check exists to catch.
  '';
assert
  undocumented == [ ]
  || throw ''
    REFUSING TO EVALUATE: the flake exports ${builtins.toString undocumented}, and the published API
    does not name it. An export nobody documented is an export a consumer will find and depend on,
    and then it is load-bearing without ever having been decided.
  '';
assert
  notAFunction == [ ]
  || throw "REFUSING TO EVALUATE: ${builtins.toString notAFunction} is published as a factory and is not a function.";
assert
  notAnAttrset == [ ]
  || throw "REFUSING TO EVALUATE: ${builtins.toString notAnAttrset} is published as data and is not an attribute set.";
assert
  hardeningMissing == [ ]
  || throw "REFUSING TO EVALUATE: lib.hardening is missing ${builtins.toString hardeningMissing}.";
pkgs.runCommand "api-surface"
  {
    meta.description = "Every symbol the published API names exists, and nothing else is exported";
  }
  ''
    echo "published API: ${lib.concatStringsSep " " promised}" > "$out"
  ''
