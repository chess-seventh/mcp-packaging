# Two factory-built services that would bind one endpoint on one host are refused
# at EVALUATION, and a host that is merely UNUSUAL is not.
#
# Every case below is a real NixOS evaluation of a synthetic host importing two
# modules built by the PUBLISHED factory - `api.mkServiceModule`, the same symbol
# a consumer calls - rather than by a relative import. What is checked is what a
# consumer would get.
#
# It needs no builder feature and no virtualisation: the whole mechanism is an
# assertion, so an evaluation is the honest depth to test it at. That matters on
# a fleet where half the boxes cannot run a virtual-machine test.
#
# ⚠ THE HALF THAT MUST NOT BE DROPPED IS THE NEGATIVE ONE. A guard that refuses
# every host would pass "it refuses a collision" and be worthless; a guard that
# refuses nothing would pass "a correct host still builds" and be worse than
# worthless, because the register would read as protection nobody has. The
# positive cases are this check's anti-vacuity proof for the negative ones and
# the negative cases are the proof for the positive ones, so neither set may be
# removed without the other losing its meaning.
{
  pkgs,
  lib,
  nixpkgs,
  system,

  # The flake's own `lib` output, passed in rather than imported - so a factory
  # that stopped being exported fails here rather than being reached anyway.
  api,
}:
let
  # ---------------------------------------------------------------------------
  # Synthetic consumers
  # ---------------------------------------------------------------------------
  # Deliberately NOT named `<something>-mcp`: `tests/unit/test_boundary.py`
  # refuses any server name in that shape that is not this repository's own, and
  # a fixture is not a reason to make an exception in the rule that keeps a
  # private roster out of a public tree. The ports are far outside the range the
  # same file guards, because a port an operator could recognise is an operator's
  # allocation wherever it is written.
  syntheticSpec = name: defaultPort: rec {
    inherit name defaultPort;

    description = "A synthetic service that exists to claim an endpoint";

    optionPath = [
      "services"
      name
    ];

    consoleScriptName = "${name}-server";

    stateDirectory = name;
    stateArea = "/var/lib/${stateDirectory}";
    serviceAccount = name;

    defaultListenAddress = "127.0.0.1";

    tokenStoreVariable = "SYNTHETIC_STATE";
    credentialsDirectoryVariable = "SYNTHETIC_CREDENTIALS_DIR";

    credentialsFileExample = "/run/secrets/${name}.example.env";
  };

  alpha = syntheticSpec "alpha-service" 19000;
  beta = syntheticSpec "beta-service" 19001;

  # Shares alpha's DEFAULT, so a host that configures neither port still
  # collides. This is the case a written registry of defaults could also have
  # caught; it is here so the register is shown to fill from the defaults as well
  # as from an override.
  gamma = syntheticSpec "gamma-service" 19000;

  portOptionOf = spec: lib.showOption (spec.optionPath ++ [ "port" ]);
  addressOptionOf = spec: lib.showOption (spec.optionPath ++ [ "listenAddress" ]);

  # ---------------------------------------------------------------------------
  # Hosts
  # ---------------------------------------------------------------------------
  # The least configuration that evaluates to a system. `pkgs.hello` stands in
  # for a packaged server: the module only interpolates its path into ExecStart,
  # and nothing here starts anything.
  baseHost = {
    boot.loader.grub.enable = false;
    fileSystems."/" = {
      device = "/dev/disk/by-label/nixos";
      fsType = "ext4";
    };
    system.stateVersion = "25.11";
  };

  factoryModules = specs: map (spec: api.mkServiceModule { inherit spec; }) specs;

  settings =
    spec: overrides:
    lib.setAttrByPath spec.optionPath (
      {
        enable = true;
        package = pkgs.hello;
        # A quoted string naming a path the host delivers at run time, because
        # the module refuses anything else and this check is not here to
        # rediscover that.
        credentialsFile = "/run/secrets/${spec.name}.env";
      }
      // overrides
    );

  host = modules: (nixpkgs.lib.nixosSystem { inherit system modules; }).config;

  # THE CASE THE WHOLE MECHANISM EXISTS FOR: beta's own default is 19001 and this
  # host moves it onto alpha's. Nothing about either module's DEFAULTS says these
  # two collide, which is exactly what a written port registry cannot see.
  configuredCollision = host (
    [ baseHost ]
    ++ factoryModules [
      alpha
      beta
    ]
    ++ [
      (settings alpha { })
      (settings beta { port = alpha.defaultPort; })
    ]
  );

  # Two services that shared a default and were never reconfigured.
  defaultCollision = host (
    [ baseHost ]
    ++ factoryModules [
      alpha
      gamma
    ]
    ++ [
      (settings alpha { })
      (settings gamma { })
    ]
  );

  # A correct two-server host: different ports, same address.
  distinctPorts = host (
    [ baseHost ]
    ++ factoryModules [
      alpha
      beta
    ]
    ++ [
      (settings alpha { })
      (settings beta { })
    ]
  );

  # ⚠ THE FALSE-POSITIVE SHAPE, AND IT IS AN ORDINARY HOST RATHER THAN A CORNER.
  # One port, two addresses: both units bind, both work. A register keyed on the
  # port alone would refuse this configuration - and a guard that refuses a
  # working host is worse than the bind failure it replaces, because it is the
  # one an operator learns to route around. Two loopback addresses are used here
  # because they are this layer's own address vocabulary; a real host would more
  # often pair loopback with a tailnet address, and the mechanism cannot tell the
  # difference between the two pairings.
  differentAddresses = host (
    [ baseHost ]
    ++ factoryModules [
      alpha
      beta
    ]
    ++ [
      (settings alpha { })
      (settings beta {
        port = alpha.defaultPort;
        listenAddress = "127.0.0.2";
      })
    ]
  );

  # A disabled service binds nothing, so it must claim nothing - even sitting on
  # a port another enabled service holds.
  disabledClaimsNothing = host (
    [ baseHost ]
    ++ factoryModules [
      alpha
      beta
    ]
    ++ [
      (settings alpha { })
      (lib.setAttrByPath beta.optionPath {
        enable = false;
        port = alpha.defaultPort;
      })
    ]
  );

  # ---------------------------------------------------------------------------
  # Reading the verdicts
  # ---------------------------------------------------------------------------
  # ⚠ MATCHED ON A MARKER, NOT ON "ANY FAILING ASSERTION". A synthetic host can
  # fail an assertion for a reason that has nothing to do with this mechanism -
  # a stale `stateVersion`, a nixpkgs change - and a check that counted those
  # would report the guard working on a day it had been deleted.
  marker = "PORT ALREADY CLAIMED";

  failedAssertions =
    config: map (entry: entry.message) (lib.filter (entry: !entry.assertion) config.assertions);

  refusals = config: lib.filter (message: lib.hasInfix marker message) (failedAssertions config);

  # Must-prove: the message names both services and both option paths. An
  # assertion that says only "port already claimed" sends the reader hunting,
  # which is the failure this mechanism exists to remove rather than to move.
  namesEverything =
    specs: message:
    lib.all (needle: lib.hasInfix needle message) (
      lib.concatMap (spec: [
        spec.name
        (portOptionOf spec)
        (addressOptionOf spec)
      ]) specs
    );

  # Must-prove: it fires during `nixos-rebuild build`, before any deploy.
  #
  # `system.build.toplevel` is what a rebuild evaluates, and NixOS throws there
  # on a failed assertion - so forcing its `drvPath` asks the same question a
  # rebuild asks, in the same place. `tryEval` catches the throw.
  #
  # ⚠ THE RESIDUE, STATED: this INSTANTIATES the system derivation, it does not
  # realise it. That is the right depth for an evaluation-time mechanism and it
  # is not the same claim as "the host builds" - nothing here compiles a kernel.
  instantiates = config: (builtins.tryEval config.system.build.toplevel.drvPath).success;

  configuredCollisionRefusals = refusals configuredCollision;
  defaultCollisionRefusals = refusals defaultCollision;
in
assert
  builtins.length configuredCollisionRefusals == 1
  || throw ''
    REFUSING TO REPORT: a host that moved one service onto another service's CONFIGURED port
    produced ${toString (builtins.length configuredCollisionRefusals)} refusals from the endpoint register, and exactly one was expected.

    This is the case the mechanism exists for and the case a written registry of default ports
    cannot see. Zero refusals means the register is not reading the configured value; more than
    one means the assertion is being emitted once per module rather than once per collision.
  '';
assert
  namesEverything [
    alpha
    beta
  ] (builtins.head configuredCollisionRefusals)
  || throw ''
    REFUSING TO REPORT: the collision message does not name both services and both option paths.

    A reader handed "port already claimed" has to go and find which two services those are and
    where each one is configured, and removing that hunt is the whole reason this fires at
    evaluation instead of leaving the second unit to fail at bind.

    The message was:

    ${builtins.head configuredCollisionRefusals}
  '';
assert
  builtins.length defaultCollisionRefusals == 1
  || throw ''
    REFUSING TO REPORT: two services sharing a DEFAULT port produced ${toString (builtins.length defaultCollisionRefusals)} refusals, and exactly one was expected.

    A register that fills only from an override would pass the configured-port case above and
    leave the commonest collision of all - two consumers that were written independently and
    picked the same number - undetected.
  '';
assert
  !(instantiates configuredCollision)
  || throw ''
    REFUSING TO REPORT: the colliding host instantiated its `system.build.toplevel` anyway.

    The assertion is in `config.assertions` and something evidently is not reading it back, so
    `nixos-rebuild build` would succeed and the collision would be found on the box - which is
    the outcome that exists today and the one this lane replaces.
  '';
assert
  refusals distinctPorts == [ ]
  || throw ''
    REFUSING TO REPORT: a correct two-server host - two services, two ports, one address - was
    refused by the endpoint register.

    A guard that fires on a working configuration is worse than the bind failure it replaces.
  '';
assert
  failedAssertions distinctPorts == [ ]
  || throw ''
    REFUSING TO REPORT: the correct two-server host fails an assertion that is not this
    mechanism's, so every negative case here is being measured against a host that was never
    valid. The failing messages were:

    ${lib.concatStringsSep "\n\n" (failedAssertions distinctPorts)}
  '';
assert
  instantiates distinctPorts
  || throw ''
    REFUSING TO REPORT: the correct two-server host does not evaluate to a system derivation.

    Refusing a genuine misconfiguration is what D-107 ruled acceptable; refusing a correct host
    is not, and nothing else in this check would notice the difference.
  '';
assert
  refusals differentAddresses == [ ]
  || throw ''
    REFUSING TO REPORT: two services on ONE port bound to two DIFFERENT addresses were refused.

    Both of those units bind and both work. Keying the register on the port alone produces
    exactly this failure, which is why it is keyed on the address and the port together - see
    `lib/portClaims.nix`. Restoring a port-only key reintroduces a guard that refuses a working
    host.
  '';
assert
  refusals disabledClaimsNothing == [ ]
  || throw ''
    REFUSING TO REPORT: a DISABLED service was refused for claiming an endpoint.

    A disabled unit binds nothing, so it can collide with nothing. Contributing its claim
    outside `mkIf cfg.enable` produces this, and it would refuse the ordinary host that keeps a
    second service defined and switched off.
  '';
pkgs.runCommand "port-claims"
  {
    meta.description = "Two services claiming one endpoint fail at evaluation, and a correct host does not";
  }
  ''
    cat > "$out" <<'REPORT'
    refused: one service moved onto another's CONFIGURED port
    refused: two services sharing a DEFAULT port
    refused: the colliding host does not instantiate system.build.toplevel
    allowed: two services, two ports, one address
    allowed: two services, one port, two addresses
    allowed: a disabled service sitting on an enabled service's port
    REPORT
  ''
