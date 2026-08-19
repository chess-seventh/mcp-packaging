# The deployed-service check, part two: the machine's own behaviour.
#
# THE SHARED LAYER ITSELF (ADR-002): parameterised, names no consumer's fact. The SECOND
# instance below is built by handing this same factory a second spec, which is
# the strongest available proof that the layer really is parameterised - if any
# consumer fact were still a literal in `mkServiceModule.nix`, two instances
# would collide on it and this check would fail rather than a later lane
# discovering it.
#
# ⚠ NEEDS A BUILDER ADVERTISING VIRTUALISATION. `nix/checks/service.nix` covers
# the ordinary contract; this one covers what only a whole machine can answer:
# a power cut, a port somebody else holds, a store that will not take a write,
# and two of these services on one box.
#
# The sandbox has NO route to whatever the consumer integrates with. Nothing
# here is a real reading and nothing here renews a real grant - what is proven
# is the SERVICE CONTRACT. Where a claim would otherwise be vacuous, the check plants what it
# needs first and says so.
#
# Each claim phrase is written NEXT TO the assertion that earns it, in the exact
# words the acceptance suite names. A phrase that drifts from its assertion turns
# a real check into a passing manifest.
{
  pkgs,
  lib,
  spec,
  serverPackage,
}:
let
  syntheticSharedSecret = "SYNTHETIC-SHARED-SECRET-3c7a1e9d5b2f4806a7c9e1b3d5f70284";
  syntheticRefreshToken = "SYNTHETIC-REFRESH-TOKEN-9f2e4a7c1b8d3560e9a2c4f6b8d0172e";

  credentialsFile = pkgs.writeText "${spec.name}-credentials.env" ''
    ${spec.clientIdVariable}=SYNTHETIC-CLIENT-ID-a2f0c7e4d9b6418fa3c5e7d9b1f4a6c8
    ${spec.clientSecretVariable}=SYNTHETIC-CLIENT-SECRET-5d3b8f1a6c9e2470b8d4f6a1c3e5079b
    ${spec.refreshTokenVariable}=${syntheticRefreshToken}
    ${spec.sharedSecretVariable}=${syntheticSharedSecret}
  '';

  # A schema-1 document the service will accept on the next start. Written by
  # the check rather than by a renewal, because the sandbox cannot renew - and
  # said out loud, because "the stored authorisation survived" is a claim about
  # the STORE surviving, not about a rotation having happened.
  #
  # `seed_digest` is the real SHA-256 of the seed in the credentials file, so the
  # precedence rule reads CONTINUE rather than treating the document as a
  # re-seed. Nix computes it here so the two cannot drift.
  storedDocument = pkgs.writeText "token.json" (
    builtins.toJSON {
      schema = 1;
      state = "committed";
      seed_digest = builtins.hashString "sha256" syntheticRefreshToken;
      refresh_token = syntheticRefreshToken;
      access_token = "SYNTHETIC-ACCESS-TOKEN-not-a-real-value";
      expires_at = 4102444800;
      userid = "synthetic-userid";
      previous_refresh_token = null;
      superseded_seed_digests = [ ];
      resume_attempts = 0;
      rotated_at = 0;
    }
  );

  # A pinned address that is NOT the every-interface set and NOT the default, so
  # "the operator chose this on purpose" and "the default is loopback" cannot be
  # satisfied by the same socket.
  #
  # A second LOOPBACK address rather than an interface address, and the first
  # version of this check is why: an address configured on `lo` through
  # `networking.interfaces` never appeared on the test machine, so the service
  # refused to start with "Cannot assign requested address" and the scenario
  # failed on the harness rather than on the module. The whole of 127/8 is bound
  # to loopback by the kernel, so 127.0.0.2 is always assignable, is not the
  # default, and is not in the every-interface set - which is all this scenario
  # needs of it.
  pinnedListenAddress = "127.0.0.2";

  serviceOptions = {
    enable = true;
    package = serverPackage;
    credentialsFile = "${credentialsFile}";
  };

  optionAttr = value: lib.setAttrByPath spec.optionPath value;
  serviceModule = import ../lib/mkServiceModule.nix { inherit spec; };

  # THE SECOND INSTANCE. Every consumer fact is different; the factory is the
  # same. This is what "the later extraction is a move rather than a redesign"
  # has to mean, tested rather than asserted.
  secondSpec = spec // {
    name = "${spec.name}-second";
    description = "${spec.description} (second instance)";
    optionPath = [
      "services"
      "${spec.name}-second"
    ];
    stateDirectory = "${spec.name}-second";
    stateArea = "/var/lib/${spec.name}-second";
    serviceAccount = "${spec.name}-second";
    defaultPort = spec.defaultPort + 1;
  };
  secondModule = import ../lib/mkServiceModule.nix { spec = secondSpec; };

  sessionProbe = import ../lib/mkSessionProbe.nix { inherit pkgs spec; };

  # ⚠ THIS USED TO BE A `curl` WHOSE ONLY ASSERTION WAS "not 000". An HTTP 500
  # satisfied it, and 500 is what the server returned to every authenticated
  # caller for the whole life of this branch. The probe opens a real session and
  # reads the tool surface back by name, so "answers" means answered.
  answers =
    address: port:
    "${sessionProbe}/bin/${spec.name}-session-probe ${address} ${toString port} ${syntheticSharedSecret}";
in
pkgs.testers.runNixOSTest {
  name = "${spec.name}-deployment";

  nodes = {
    # Nothing configured beyond what the service needs: the listen address is
    # left to the module's own default.
    defaults =
      { ... }:
      {
        imports = [ serviceModule ];
        config = optionAttr serviceOptions;
      };

    # An operator putting the service on one interface deliberately.
    pinned =
      { ... }:
      {
        imports = [ serviceModule ];
        config = optionAttr (serviceOptions // { listenAddress = pinnedListenAddress; });
      };

    # Something else already holds the port. A socket unit takes it at
    # sockets.target, long before this service is started.
    contended =
      { ... }:
      {
        imports = [ serviceModule ];
        config = optionAttr serviceOptions // {
          systemd.sockets.port-squatter = {
            wantedBy = [ "sockets.target" ];
            listenStreams = [ "${spec.defaultListenAddress}:${toString spec.defaultPort}" ];
          };
          systemd.services.port-squatter.serviceConfig = {
            ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
          };
        };
      };

    # Two of these services, from one factory and two specs.
    twinned =
      { ... }:
      {
        imports = [
          serviceModule
          secondModule
        ];
        # mkMerge, NOT `//`. The two option paths share their first component, so
        # a shallow update makes the second `services` attrset REPLACE the first
        # and only one instance is configured - which reads at run time as "the
        # unit does not exist" rather than as a merge mistake.
        config = lib.mkMerge [
          (optionAttr serviceOptions)
          (lib.setAttrByPath secondSpec.optionPath serviceOptions)
        ];
      };

    # A store the service's own account cannot write through. The unit's state
    # directory is mounted read-only for this unit alone, which is a machine-level
    # fault rather than a mode the service could repair.
    unwritable =
      { ... }:
      {
        imports = [ serviceModule ];
        config = optionAttr serviceOptions // {
          systemd.services.${spec.name}.serviceConfig.ReadOnlyPaths = [ spec.stateArea ];
        };
      };
  };

  testScript = ''
    start_all()

    defaults.wait_for_unit("${spec.name}.service")
    defaults.wait_for_open_port(${toString spec.defaultPort})

    # ------------------------------------------------------------------
    # The store the assertions read is the real one
    # ------------------------------------------------------------------
    # finds the store is a real directory rather than a link
    #
    # Asked with -h so a symbolic link answers as a link rather than as whatever
    # it points at. Under a disappearing account the state area IS a link, and an
    # assertion written against the visible path would read through it and pass
    # while saying nothing about the real directory - a design that LOOKS proven,
    # guarding a credential nobody can recover. ADR-008 chose a fixed account for
    # exactly this reason, and this is the assertion that holds it to it.
    defaults.fail("test -h ${spec.stateArea}")
    defaults.succeed("test -d ${spec.stateArea}")

    # finds the store owned by the service's own account
    owner = defaults.succeed("stat -c '%U:%G' ${spec.stateArea}").strip()
    assert owner == "${spec.serviceAccount}:${spec.serviceAccount}", (
        f"the store is owned by {owner}, not by the service's own account"
    )

    # finds the store readable by that account alone
    mode = defaults.succeed("stat -c '%a' ${spec.stateArea}").strip()
    assert mode == "700", f"the store is mode {mode}; anything but 700 is readable by somebody else"

    # ------------------------------------------------------------------
    # With nothing configured, it listens only where nothing outside can reach
    # ------------------------------------------------------------------
    # finds the complete set of listening sockets is the loopback address alone
    #
    # The COMPLETE set, not "the expected one is present". A second socket on
    # another address is exactly the failure this scenario exists to catch, and
    # grepping for the one you wanted cannot see it.
    listening = defaults.succeed(
        "${pkgs.iproute2}/bin/ss -ltnH | ${pkgs.gawk}/bin/awk '{print $4}' | sort -u"
    ).split()
    assert listening == ["${spec.defaultListenAddress}:${toString spec.defaultPort}"], (
        f"the machine is listening on {listening}, and the default must be the loopback address alone"
    )

    # ------------------------------------------------------------------
    # Power-cycling the box costs no re-authorisation
    # ------------------------------------------------------------------
    # The store is seeded FIRST, because a power cut over an empty store proves
    # nothing: an empty store is unchanged by everything.
    defaults.succeed(
        "install -o ${spec.serviceAccount} -g ${spec.serviceAccount} -m 600"
        " ${storedDocument} ${spec.stateArea}/token.json"
    )
    # ⚠ FLUSHED ON PURPOSE, and the first run of this check is why. `install`
    # leaves the bytes in the page cache, and a power cut does not write the page
    # cache out - so the document vanished and the assertion below failed against
    # a store that had never really held it. The service's own write fsyncs the
    # file AND the directory before it returns (ADR-004 section 3), which is
    # exactly the difference; planting a document without that would be testing a
    # weaker write than the one that ships.
    defaults.succeed("sync ${spec.stateArea}/token.json ${spec.stateArea}")
    before = defaults.succeed("sha256sum ${spec.stateArea}/token.json").split()[0]

    # power-cycles that machine
    #
    # crash(), not shutdown(): a clean stop flushes, and flushing is the thing a
    # power cut does not do. This is the case ADR-004's durable write exists for.
    defaults.crash()
    defaults.start()

    # finds the service came up unaided
    #
    # Nothing is started by hand between the two lines above and this one.
    defaults.wait_for_unit("${spec.name}.service")
    defaults.wait_for_open_port(${toString spec.defaultPort})

    # finds the stored authorisation unchanged
    #
    # By CONTENT. "The directory still exists" is satisfied by a store the
    # service emptied, and the value being protected is the bytes.
    after = defaults.succeed("sha256sum ${spec.stateArea}/token.json").split()[0]
    assert after == before, "the stored authorisation changed across a power cut"

    # and the service answering afterwards, which is what makes the survival
    # useful rather than merely tidy.
    defaults.succeed("${answers spec.defaultListenAddress spec.defaultPort}")

    # ------------------------------------------------------------------
    # An operator can put the service on a specific interface on purpose
    # ------------------------------------------------------------------
    pinned.wait_for_unit("${spec.name}.service")
    # ON THE PINNED ADDRESS. `wait_for_open_port` defaults to localhost, so the
    # default spelling waits fifteen minutes for a socket that was deliberately
    # bound somewhere else and then reports a timeout rather than the truth. The
    # address is the subject of this scenario; it cannot be left implicit.
    pinned.wait_for_open_port(${toString spec.defaultPort}, addr = "${pinnedListenAddress}", timeout = 120)

    # finds the complete set of listening sockets is that address alone
    pinned_sockets = pinned.succeed(
        "${pkgs.iproute2}/bin/ss -ltnH | ${pkgs.gawk}/bin/awk '{print $4}' | sort -u"
    ).split()
    assert pinned_sockets == ["${pinnedListenAddress}:${toString spec.defaultPort}"], (
        f"the machine is listening on {pinned_sockets}, and the configured address must be the only one"
    )
    # and the default it was moved OFF is genuinely no longer bound, which is the
    # half that makes "that address alone" mean anything.
    pinned.fail(
        "${pkgs.iproute2}/bin/ss -ltnH | grep -q '${spec.defaultListenAddress}:${toString spec.defaultPort}'"
    )

    # ------------------------------------------------------------------
    # A port something else already holds is explained rather than dumped
    # ------------------------------------------------------------------
    contended.wait_for_unit("multi-user.target")
    # WAIT FOR THE TERMINAL STATE, not merely for "not active". Between the
    # attempts a Restart=on-failure unit sits in `activating (auto-restart)`,
    # which is not active and is not failed either - so asking whether it failed
    # at that instant answers no, and the scenario reads as "it kept trying" when
    # it is about to stop. `failed` arrives only once StartLimitBurst is spent,
    # and that is the state the scenario names.
    contended.wait_until_succeeds("systemctl is-failed --quiet ${spec.name}.service", timeout = 180)
    refusal = contended.succeed("journalctl -u ${spec.name}.service --no-pager -o cat")

    # finds the failure names the address and the port
    #
    # Both, and by value. An operator reading a journal cannot act on "address
    # already in use" without being told WHICH address.
    assert "${spec.defaultListenAddress}:${toString spec.defaultPort}" in refusal, (
        "the refusal does not name the address and the port it could not take"
    )

    # finds the failure says what to do about it
    assert "Choose a different port" in refusal, "the refusal names no remedy, so it is a puzzle rather than a guard"

    # finds the service failed rather than looping against a held port
    #
    # StartLimitBurst turns a unit nothing can fix into one that stops trying.
    # A flapping unit produces an alert nobody can act on and hides the cause
    # underneath it.
    assert "start-limit-hit" in refusal, (
        "the unit never hit its start limit, so nothing stopped it re-presenting itself to a held port"
    )

    # ------------------------------------------------------------------
    # Two of these services run on one box without displacing each other
    # ------------------------------------------------------------------
    twinned.wait_for_unit("${spec.name}.service")
    twinned.wait_for_unit("${secondSpec.name}.service")

    # finds both listening
    twinned.wait_for_open_port(${toString spec.defaultPort})
    twinned.wait_for_open_port(${toString secondSpec.defaultPort})

    # finds neither has displaced the other
    #
    # Both answering AFTER both are up. Started-then-displaced looks identical to
    # never-started if only the second is asked.
    twinned.succeed("${answers spec.defaultListenAddress spec.defaultPort}")
    twinned.succeed("${answers secondSpec.defaultListenAddress secondSpec.defaultPort}")

    # finds each keeping its authorisation in its own store
    #
    # Two directories, two accounts, and neither readable by the other. One
    # shared store would make a rotation by either instance spend the other's
    # authorisation.
    assert twinned.succeed("stat -c '%U' ${spec.stateArea}").strip() == "${spec.serviceAccount}"
    assert twinned.succeed("stat -c '%U' ${secondSpec.stateArea}").strip() == "${secondSpec.serviceAccount}"
    twinned.fail(
        "${pkgs.util-linux}/bin/setpriv --reuid=${secondSpec.serviceAccount} --regid=${secondSpec.serviceAccount}"
        " --clear-groups test -r ${spec.stateArea}/."
    )

    # ------------------------------------------------------------------
    # A store the service cannot write stops it before it opens a socket
    # ------------------------------------------------------------------
    unwritable.wait_for_unit("multi-user.target")
    unwritable.wait_until_succeeds("systemctl is-failed --quiet ${spec.name}.service", timeout = 180)
    store_refusal = unwritable.succeed("journalctl -u ${spec.name}.service --no-pager -o cat")

    # finds the service failed naming the store
    #
    # The refusal names the check AND the path. A unit that fails without saying
    # which store it could not write leaves an operator guessing between the
    # state area, the credentials directory and the package.
    assert "store_write_path_broken" in store_refusal, "the refusal does not name the check that refused"
    assert "${spec.stateArea}" in store_refusal, "the refusal does not name the store it could not write"

    # finds nothing listening
    unwritable.fail("${pkgs.iproute2}/bin/ss -ltnH | grep -q ':${toString spec.defaultPort} '")

    # finds the consumer's upstream was never contacted
    #
    # By CONSTRUCTION rather than by observation, and that is the stronger claim:
    # ADR-004 section 8 makes the whole probe path unable to import an HTTP
    # client, so the refusal above happened before anything that COULD reach the
    # vendor was loaded. The observable half is that the process refused at the
    # probe rather than at the transport - a transport refusal would mean the
    # session had already been built.
    assert "health.startup.refused" in store_refusal, (
        "the process did not refuse at the startup probe, so it had already built a session that can reach the upstream"
    )
    unwritable.fail("journalctl -u ${spec.name}.service --no-pager | grep -q 'an-upstream-host'")
  '';
}
