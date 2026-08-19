# The deployed-service check: a NixOS virtual-machine test.
#
# THE SHARED LAYER ITSELF (ADR-002): parameterised, names no consumer's fact.
#
# ⚠ THIS NEEDS A BUILDER ADVERTISING VIRTUALISATION. It cannot run on every box
# in this fleet, and the machine this lane was built on is one of the ones that
# cannot. That is why the closure secret-search is a separate check that needs
# only a builder: the headline guarantee must not be gated behind a capability
# half the fleet lacks.
#
# The sandbox has no route to whatever the consumer integrates with, so nothing
# asserted here is a real reading from it. These are claims about the SERVICE CONTRACT: that the unit
# starts, reports ready when it is really ready, refuses what it should refuse,
# and keeps the rotating authorisation across a restart.
#
# Each claim phrase below is written NEXT TO the assertion that earns it. A phrase that drifts from its
# assertion turns a real check into a passing manifest.
{
  pkgs,
  lib,
  spec,
  serverPackage,
}:
let
  fixtures = import ../lib/fixtures.nix { inherit pkgs spec; };
  syntheticSharedSecret = fixtures.sharedSecret;

  serviceOptions = {
    enable = true;
    package = serverPackage;
    listenAddress = spec.defaultListenAddress;
    credentialsFile = fixtures.hostPath;
  };

  optionAttr = value: lib.setAttrByPath spec.optionPath value;
  sessionProbe = import ../lib/mkSessionProbe.nix { inherit pkgs spec; };

  # ⚠ THE STATE DOCUMENT IS THE CONSUMER'S, AND IT IS OPTIONAL. A server that
  # persists a credential it must not lose declares `spec.stateDocument`, and the
  # restart-survival block below runs. A server with nothing durable to keep -
  # which is three of the four named future consumers - declares nothing, and the
  # block is REPLACED BY A LINE SAYING SO rather than silently dropped.
  #
  # Silence is the failure mode this repository has met four times: a check whose
  # assertions evaporate when a field is absent reports the same green as one
  # that ran them. The `spec` fragment is the consumer's own document, verbatim,
  # because only the consumer knows what its store holds - this layer owns the
  # DURABILITY question and never the schema.
  keepsState = spec ? stateDocument;
  storeDocumentName = if keepsState then spec.stateDocument.name else "";
  storedDocument =
    if keepsState then pkgs.writeText storeDocumentName spec.stateDocument.text else null;
in
pkgs.testers.runNixOSTest {
  name = "${spec.name}-service";

  nodes = {
    # The ordinary machine: everything supplied correctly.
    supplied =
      { ... }:
      {
        imports = [
          (import ../lib/mkServiceModule.nix { inherit spec; })
          fixtures.hostModule
        ];
        config = optionAttr serviceOptions;
      };

    # The machine whose credentials file is simply not there. systemd's
    # LoadCredential fails the unit by itself, before ExecStart runs, which is
    # the whole reason ADR-006 chose it over an EnvironmentFile plus a
    # hand-written presence check.
    starved =
      { ... }:
      {
        imports = [
          (import ../lib/mkServiceModule.nix { inherit spec; })
          fixtures.hostModule
        ];
        config = optionAttr (serviceOptions // { credentialsFile = "/run/secrets/absent-on-purpose.env"; });
      };
  };

  testScript = ''
    start_all()

    # boots that machine and waits for the service
    #
    # waits for that readiness signal rather than for the process: the unit is
    # Type=notify, so `wait_for_unit` returns when the server has sent READY=1,
    # which it does only after the listener is bound and accepting. A Type=simple
    # unit would report active the moment the process existed and everything
    # below would race its own subject.
    supplied.wait_for_unit("${spec.name}.service")
    supplied.wait_for_open_port(${toString spec.defaultPort})

    # sends the shared secret with that request, and
    # asks for the tools this server offers and gets them.
    #
    # The sandbox cannot reach the consumer's upstream, so what is proven is the CONTRACT:
    # a caller holding the secret is admitted and reaches the tool surface, and
    # the surface names every tool the spec declares.
    # ⚠ THIS USED TO ASSIGN curl's OUTPUT TO A VARIABLE NOBODY READ, with a
    # trailing `|| true` swallowing its exit status, under a comment claiming the
    # caller "reaches the tool surface, and the surface names the measurements".
    # Nothing measured that, and what it hid was a server that answered HTTP 500
    # to every caller who HELD the secret - for the whole life of this branch.
    #
    # The probe opens a real session, requires a session id, and reads every tool
    # name back. It exits non-zero on anything less, so `succeed` is the assertion.
    supplied.succeed(
        "${sessionProbe}/bin/${spec.name}-session-probe"
        " ${spec.defaultListenAddress} ${toString spec.defaultPort} ${syntheticSharedSecret}"
    )

    # A caller WITHOUT the secret gets the one refusal, and it carries no reason.
    refused_status = supplied.succeed(
        "curl --silent --output /dev/null --write-out '%{http_code}'"
        " -X POST http://${spec.defaultListenAddress}:${toString spec.defaultPort}/mcp"
        " -d '{}'"
    ).strip()
    assert refused_status == "401", f"an unauthenticated caller got {refused_status}, not 401"

    # The rotating authorisation lives in the state area, owned by the service
    # account alone, and its modes are the guarantee rather than a nicety.
    supplied.succeed("test -d ${spec.stateArea}")
    state_mode = supplied.succeed("stat -c '%a %U' ${spec.stateArea}").strip()
    assert state_mode.startswith("700 "), f"the state area is {state_mode}, not 700 owned by the service"

    # finds the place the credentials arrive is not writable
    #
    # systemd mounts the credentials directory read-only. That is what makes the
    # server the ONLY writer of the rotating authorisation (ADR-003): it cannot
    # write back over the seed even if it tried.
    supplied.fail("test -w /run/credentials/${spec.name}.service")

    ${
      if keepsState then
        ''
          # finds the renewed authorisation written somewhere else entirely
          #
          # The renewed authorisation belongs in the state area, never beside the seed.
          # Two lifetimes, two places.
          supplied.succeed("test ! -e /run/credentials/${spec.name}.service/${storeDocumentName}")

          # ⚠ SEEDED FIRST, AND ASSERTED TO BE THERE. The sandbox cannot renew, so this
          # store is EMPTY - and the first version of this assertion compared
          # `sha256sum … || echo absent` against itself, which is "absent" on both
          # sides and passes over a store the service has wiped. That is the same
          # measuring-nothing shape this check exists to catch, introduced by the
          # commit that was fixing another one.
          supplied.succeed(
              "install -o ${spec.serviceAccount} -g ${spec.serviceAccount} -m 600"
              " ${storedDocument} ${spec.stateArea}/${storeDocumentName}"
          )
          supplied.succeed("test -s ${spec.stateArea}/${storeDocumentName}")
          before_restart = supplied.succeed("sha256sum ${spec.stateArea}/${storeDocumentName}").split()[0]

          # restarts the service
          supplied.succeed("systemctl restart ${spec.name}.service")
          supplied.wait_for_unit("${spec.name}.service")
          supplied.wait_for_open_port(${toString spec.defaultPort})

          # finds the stored authorisation unchanged
          #
          # A restart must not spend the grant. This is the property the whole lane
          # exists to protect: a rotation costs a browser re-authorisation if it goes
          # wrong, and a restart is not a reason to rotate.
          #
          # ⚠ BY CONTENT, over a document that is REALLY THERE. `test -d` on the state
          # area was satisfied by a store the service had emptied; a digest with a
          # fallback on both sides was satisfied by there being no document at all. The
          # value being protected is the bytes, so the bytes are what is compared - and
          # the file has to exist for the comparison to mean anything.
          supplied.succeed("test -s ${spec.stateArea}/${storeDocumentName}")
          after_restart = supplied.succeed("sha256sum ${spec.stateArea}/${storeDocumentName}").split()[0]
          assert after_restart == before_restart, "the stored authorisation changed across a restart"
        ''
      else
        ''
          # ⚠ NOT ASSERTED HERE, AND SAID OUT LOUD RATHER THAN DROPPED: this consumer
          # declares no `spec.stateDocument`, so it keeps nothing across a restart that
          # this check could compare. The restart itself is still exercised below.
          print("NOT ASSERTED: restart survival of a stored credential - this consumer declares no stateDocument")

          supplied.succeed("systemctl restart ${spec.name}.service")
          supplied.wait_for_unit("${spec.name}.service")
          supplied.wait_for_open_port(${toString spec.defaultPort})
        ''
    }

    # finds the service answering afterwards
    # The SAME probe, not a weaker one: "answering afterwards" has to mean what
    # it meant before the restart, or a restart that broke the session manager
    # would read as a pass.
    supplied.succeed(
        "${sessionProbe}/bin/${spec.name}-session-probe"
        " ${spec.defaultListenAddress} ${toString spec.defaultPort} ${syntheticSharedSecret}"
    )

    # The starved machine: no credentials file at all.
    #
    # finds the service failed
    #
    # ⚠ THIS LINE USED TO BE `systemctl is-failed … || true`, WHICH ALWAYS
    # SUCCEEDS. So "finds the service failed" was carried entirely by a
    # `wait_until_fails` on `is-active`, which proves only NOT ACTIVE - satisfied
    # by a unit that never started, was stopped, or is still activating. This
    # file names a trailing `|| true` as the exact defect it fixed elsewhere, and
    # then had one.
    #
    # ⚠ AND WAITING IS THE WHOLE OF IT, WHICH THE FIRST FIX GOT WRONG. Asserting
    # the state once, straight after `wait_until_fails`, reported `activating`:
    # the unit has `Restart=on-failure` with a ten-second gap, so it cycles
    # failed -> activating -> failed and only SETTLES at failed once the start
    # limit trips. So this waits for the settled state rather than sampling a
    # cycling one - the same shape `deployment.nix` already uses for its
    # port-contended node, for the same reason.
    starved.wait_until_fails("systemctl is-active --quiet ${spec.name}.service")
    starved.wait_until_succeeds("systemctl is-failed --quiet ${spec.name}.service", timeout = 180)

    # finds the server's own first instruction never ran
    #
    # LoadCredential fails the unit BEFORE ExecStart, so the server process never
    # started - which is stronger than it having started and refused, because a
    # process that never ran cannot have reached anything off the machine.
    #
    # ⚠ ASKED OF ExecMainPID, NOT OF THE JOURNAL. This line used to grep the
    # journal for the console script's name and require it ABSENT - and systemd
    # prints that very name in its own failure line, because the executable it
    # could not spawn is part of the message. So the assertion could not be
    # satisfied by any machine on which systemd said why it had failed, which is
    # every machine. It also hardcoded ONE consumer's script name in a file ADR-002
    # says may name none.
    #
    # ExecMainPID is NOT the discriminator and was tried first: systemd forks the
    # child, and the child fails at a setup STEP before it ever execs the binary,
    # so the field holds a real pid on a unit whose ExecStart never ran.
    #
    # The step systemd names IS the claim. It says CREDENTIALS, which is the step
    # before exec, and it says it in systemd's own vocabulary rather than in a
    # string this repository chose.
    starved.succeed("journalctl -u ${spec.name}.service | grep -q 'Failed at step CREDENTIALS'")
    supplied.fail("journalctl -u ${spec.name}.service | grep -q 'Failed at step'")

    # and the server itself wrote nothing at all: every line it can write is a
    # JSON event, so their absence is the process's own silence rather than
    # systemd's.
    starved.fail("journalctl -u ${spec.name}.service | grep -q '\"event\"'")

    # finds nothing listening
    starved.fail("${pkgs.iproute2}/bin/ss -ltn | grep -q ':${toString spec.defaultPort} '")
  '';
}
