# The build-system overlay: supply a build backend to a package whose own is not
# resolvable from the lock file.
#
# ⚠ WHY IT IS ITS OWN FILE, AND WHY IT TAKES A SPEC RATHER THAN A NAME. This was
# `packagesNeedingSetuptools`, a list of names whose fix was the literal
# `resolveBuildSystem { setuptools = [ ]; }` written inside `mkServerPackage.nix`.
# That argument could not fix the case it was most needed for, and the case is
# this layer itself: consumed from a GIT source, `mcp-packaging` has neither an
# sdist nor a wheel entry in a consumer's `uv.lock`, so nothing says what to
# build it with, and its own `hatchling` backend is not importable in the
# isolated build environment. The one escape hatch supplied setuptools; this
# distribution builds with hatchling; so no argument the published API offered
# could build this layer from outside its own tree. Measured on 2026-08-19 from
# the first external consumer, which the naming rule keeps unnamed here (L185).
#
# Extracted so the mechanism can be PROVEN rather than asserted:
# `nix/checks/build-system-hook.nix` applies it to a stub package set and reads
# back what reached `resolveBuildSystem`. A fix living inline in a `let` block is
# reachable only by building something that needs it.
{
  # Distribution name -> a uv2nix build-system spec, e.g.
  # `{ mcp-packaging = { hatchling = [ ]; }; }`. Each entry supplies a MISSING
  # BUILD SYSTEM and never changes a version - that distinction is what keeps the
  # lock file the only thing deciding what lands in the closure.
  packagesNeedingBuildSystems,
}:
final: prev:
builtins.mapAttrs (
  name: buildSystemSpec:
  prev.${name}.overrideAttrs (old: {
    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ final.resolveBuildSystem buildSystemSpec;
  })
) packagesNeedingBuildSystems
