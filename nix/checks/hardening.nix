# The tightening set, read back off the RUNNING service.
#
# THE SHARED LAYER ITSELF (ADR-002): parameterised, names no consumer's fact.
#
# ⚠ NEEDS A BUILDER ADVERTISING VIRTUALISATION.
#
# WHY THIS CHECK EXISTS AT ALL. `lib/hardening.nix` holds 28 tightening
# directives and states that they are applied WHOLE - "a directive quietly left
# out is a weaker posture than the module promises". Nothing held it to that.
# (This header used to attribute both the set and the sentence to
# `mkServiceModule.nix`, misquote the sentence, and call 28 "about twenty" -
# while the same file, sixty lines down, correctly says the tables moved.) A directive deleted in a hurry, or silently dropped by a systemd
# that no longer understands it, leaves a unit that starts, answers, passes every
# other check in this repository, and is not the unit the module describes.
#
# ⚠ TWO SOURCES, AND THE FIRST VERSION HAD ONLY ONE. It derived the expected set
# from the module's own serviceConfig and filtered BOTH sides by what the module
# currently sets - which catches a directive ADDED and not tabled, and is blind to
# a directive DELETED, because a deletion removes it from the expected side and
# the asked side at once. Measured: deleting `ProtectClock = true;` from the
# module left this check at exit 0, in a file whose own header says it exists to
# catch "a directive deleted in a hurry".
#
# So completeness needs a derived source AND a recorded one, and they answer
# different questions:
#
#   * DERIVED from the module (`unchecked`): a tightening this check cannot read
#     back makes it refuse to run at all. Catches additions.
#   * RECORDED (`requiredPosture`): a tightening that must be present makes it
#     refuse when the module stops setting it. Catches deletions.
#
# ⚠ BOTH RECORDS NOW LIVE IN `lib/hardening.nix`, AND BOTH QUESTIONS ARE ALSO
# ASKED AT EVALUATION THERE. That is the change this extraction made, and it is
# an improvement rather than a relocation: this check needs a builder advertising
# virtualisation, and half the boxes in the fleet it serves have none - so on
# those, the completeness bookkeeping simply never ran. It now runs wherever nix
# evaluates, for every consumer, and the two assertions below are kept as the
# backstop that reads the ACTUAL module the VM built rather than the table.
#
# The property names systemd reports are not always the directive names, and the
# values are not always the values written. Both were MEASURED on a running unit
# rather than assumed.
#
# Each claim phrase is written NEXT TO the assertion that earns it.
{
  pkgs,
  lib,
  spec,
  serverPackage,
}:
let
  fixtures = import ../lib/fixtures.nix { inherit pkgs spec; };
  syntheticSharedSecret = fixtures.sharedSecret;

  serviceModule = import ../lib/mkServiceModule.nix { inherit spec; };

  serviceOptions = {
    enable = true;
    package = serverPackage;
    listenAddress = spec.defaultListenAddress;
    credentialsFile = fixtures.hostPath;
  };

  optionAttr = value: lib.setAttrByPath spec.optionPath value;

  # ⚠ THE FOUR TABLES ARE NOT WRITTEN HERE ANY MORE. They used to be, in
  # systemd's rendering, while the module carried the same set in Nix spelling -
  # two copies of a safety-critical list kept in agreement by hand, in two files
  # that ADR-002 was about to put in two different repositories.
  #
  # Both halves now come from `lib/hardening.nix`, which holds them as data and
  # asserts at EVALUATION that they agree: a directive dropped from the applied
  # set while `required` still names it, or applied while no table can read it
  # back, fails to evaluate by name. That is the completeness bookkeeping this
  # script used to do, moved to where every consumer gets it without a builder
  # that advertises virtualisation.
  #
  # What is left HERE is the half only a running unit can answer: whether the
  # tightening that is claimed is the tightening that is RUNNING.
  inherit (import ../lib/hardening.nix) posture;

  inherit (posture) booleanDirectives stringDirectives notTightenings;
  requiredPosture = posture.required;

  # Syscalls the denied groups contain. Present in the resolved allow list would
  # mean a group was not denied after all. Chosen one per denied group so the
  # assertion fails for the RIGHT reason rather than on an incidental name.
  forbiddenSyscalls = [
    "mount" # @mount
    "ptrace" # @debug
    "bpf" # @privileged
    "kexec_load" # @privileged
    "swapon" # @swap
    "modify_ldt" # @cpu-emulation
  ];
  sessionProbe = import ../lib/mkSessionProbe.nix { inherit pkgs spec; };
in
pkgs.testers.runNixOSTest {
  name = "${spec.name}-hardening";

  nodes.box =
    { ... }:
    {
      imports = [
        serviceModule
        fixtures.hostModule
      ];
      config = optionAttr serviceOptions;
    };

  testScript =
    { nodes, ... }:
    let
      applied = nodes.box.systemd.services.${spec.name}.serviceConfig;
      appliedNames = builtins.attrNames applied;

      # Every directive the module actually sets, minus the ones declared not to
      # be part of the posture, minus the ones this check knows how to ask about.
      # Anything left is a tightening nobody checks.
      unchecked = lib.subtractLists (
        booleanDirectives ++ builtins.attrNames stringDirectives ++ notTightenings
      ) appliedNames;

      # The other half: a directive the recorded posture requires and the module
      # no longer sets at all.
      dropped = lib.subtractLists appliedNames requiredPosture;

      booleanChecks = lib.concatMapStringsSep "\n" (name: ''
        expected = "${if applied.${name} then "yes" else "no"}"
        seen = box.succeed("systemctl show ${spec.name}.service -p ${name} --value").strip()
        assert seen == expected, (
            f"${name} reads back as {seen!r} and the module declares {expected!r}. "
            "The tightening that is claimed is not the tightening that is running."
        )
        checked.add("${name}")
      '') (builtins.filter (name: builtins.elem name appliedNames) booleanDirectives);

      stringChecks = lib.concatStringsSep "\n" (
        lib.mapAttrsToList (name: expected: ''
          seen = box.succeed("systemctl show ${spec.name}.service -p ${name} --value").strip()
          assert seen == "${expected}", (
              f"${name} reads back as {seen!r} and the module declares '${expected}'. "
              "The tightening that is claimed is not the tightening that is running."
          )
          checked.add("${name}")
        '') (lib.filterAttrs (name: _: builtins.elem name appliedNames) stringDirectives)
      );
    in
    ''
      ${
        lib.optionalString (dropped != [ ]) ''
          raise Exception(
              "REFUSING TO REPORT: the module no longer sets ${builtins.toString dropped}, and the "
              "recorded posture requires it. Dropping a tightening is a weakening of what this "
              "service promises to the health record it holds; if it is deliberate, take the name "
              "out of requiredPosture in the same commit, so the diff shows the promise changing."
          )
        ''
      }${
        lib.optionalString (unchecked != [ ]) ''
          raise Exception(
              "REFUSING TO REPORT: the module sets ${builtins.toString unchecked}, and this check "
              "does not know how to read those back. A tightening nobody checks is exactly what this "
              "check exists to make impossible, so it fails rather than passing over them. Add each "
              "to booleanDirectives or stringDirectives with the value systemd reports, or to "
              "notTightenings with a reason."
          )
        ''
      }
      start_all()
      box.wait_for_unit("${spec.name}.service")
      box.wait_for_open_port(${toString spec.defaultPort})

      checked = set()

      # reads every tightening setting back off the running service
      #
      # Off the RUNNING service, through systemctl show, never off the unit file
      # on disk. A unit file states an intention; a running service states what
      # the kernel actually applied, and the two differ whenever systemd does not
      # understand a directive.
      ${booleanChecks}
      ${stringChecks}

      # The two capability directives report an empty string when the set is
      # empty, which is the answer wanted and is also what an unset directive
      # reports. So they are asked of the PROCESS instead: an empty bounding set
      # means the running process holds no capability at all.
      capabilities = box.succeed(
          "grep -E '^Cap(Prm|Eff|Bnd):' /proc/$(systemctl show ${spec.name}.service -p MainPID --value)/status"
      )
      for line in capabilities.strip().splitlines():
          name, value = line.split()
          assert int(value, 16) == 0, f"{name} is {value}, and the module declares an empty capability set"
      checked.update({"CapabilityBoundingSet", "AmbientCapabilities"})

      # The syscall filter resolves to an allow list hundreds of names long, so
      # comparing it as a string would compare this systemd's idea of
      # @system-service rather than the module's decision. What the module
      # decided is which GROUPS are denied, so that is what is asked: one
      # representative syscall per denied group must be absent from the resolved
      # list.
      resolved = box.succeed("systemctl show ${spec.name}.service -p SystemCallFilter --value").split()
      assert len(resolved) > 100, (
          f"the resolved syscall filter holds {len(resolved)} entries, which is not a resolved "
          "@system-service allow list. An empty or tiny filter would make every absence below trivially true."
      )
      for forbidden in ${builtins.toJSON forbiddenSyscalls}:
          assert forbidden not in resolved, (
              f"{forbidden} is in the resolved syscall allow list, so the group denying it is not denied"
          )
      checked.add("SystemCallFilter")

      # ReadWritePaths is written out EMPTY on purpose, so that the day something
      # needs adding it is a visible diff. Asserted as empty rather than skipped.
      assert box.succeed("systemctl show ${spec.name}.service -p ReadWritePaths --value").strip() == "", (
          "ReadWritePaths is no longer empty; the module says that day must be a visible diff"
      )
      checked.add("ReadWritePaths")

      # compares the whole set rather than a sample of it
      #
      # The count is derived from the module's own serviceConfig at evaluation
      # time and from what this run actually asked at run time. They must agree,
      # which is what stops a directive being added to the module and quietly not
      # checked - the failure mode a hand-written list has by design.
      expected_posture = set(${
        builtins.toJSON (
          lib.subtractLists notTightenings (
            builtins.filter (n: builtins.elem n appliedNames) (
              booleanDirectives ++ builtins.attrNames stringDirectives
            )
          )
        )
      }) | {"CapabilityBoundingSet", "AmbientCapabilities", "SystemCallFilter", "ReadWritePaths"}
      assert checked == expected_posture, (
          f"this run asked about {sorted(checked)} and the module declares {sorted(expected_posture)}. "
          "A posture compared in part is a posture nobody has compared."
      )

      # finds the service still answering with all of it applied
      #
      # ⚠ THE PROBE, not a status code. "not 000" was satisfied by the HTTP 500
      # this server returned to every authenticated caller, so the tightening
      # could have cost the service everything and this line would have passed.
      box.succeed(
          "${sessionProbe}/bin/${spec.name}-session-probe"
          " ${spec.defaultListenAddress} ${toString spec.defaultPort} ${syntheticSharedSecret}"
      )

      # ------------------------------------------------------------------
      # Tightening the service does not cost it its startup probe
      # ------------------------------------------------------------------
      # proves the probe ran under every directive above, and did not refuse
      #
      # ⚠ THIS HEADING USED TO SAY "still stores a renewed authorisation", and
      # justified itself with a sentinel written through the durable write that a
      # rotation goes through. Neither exists here: the durable write did not move
      # into this layer, and a consumer supplies its own probe checks - the
      # example one has no write-path check at all, so no sentinel is ever
      # written. Two assertions were carrying a phrase about durability that
      # nothing in them measured, in a file whose own header calls that shape "a
      # passing manifest".
      #
      # What they DO prove, and it is worth proving: the probe ran with every
      # tightening applied and did not refuse. A directive that broke the store's
      # modes or its write path is refused BY the probe, so this is the check that
      # a consumer whose probe does exercise its store gets for free.
      #
      # The anti-vacuity half: the probe must genuinely have run. A refusal event
      # would mean it ran and refused; no event at all plus an active unit is the
      # only shape that means it ran and passed, so the absence is asserted
      # against a unit that IS active rather than on its own.
      box.succeed("systemctl is-active --quiet ${spec.name}.service")
      box.fail("journalctl -u ${spec.name}.service --no-pager | grep -q 'health.startup.refused'")

      # proves the service still answers a question
      #
      # The tool surface, reached through the guarded transport. The sandbox has
      # no route to the vendor, so a real measurement is not available and is not
      # claimed; what is claimed is that the tightening did not cost the service
      # the ability to be asked.
      box.succeed(
          "${sessionProbe}/bin/${spec.name}-session-probe"
          " ${spec.defaultListenAddress} ${toString spec.defaultPort} ${syntheticSharedSecret}"
      )

      # ------------------------------------------------------------------
      # The store stays private to the service under the whole tightening
      # ------------------------------------------------------------------
      # reads the store and every file in it by walking the directory
      #
      # WALKED, never named. A check that stats the one file it expects reports
      # a private store while a second file sits beside it world-readable, and a
      # second file is exactly what an interrupted rotation leaves behind.
      #
      # A file is planted first, deliberately wide, because a walk over an empty
      # store finds nothing and reports it as clean - the vacuity this repository
      # keeps meeting. The service's own probe must then make it private, which
      # proves the MECHANISM rather than the ambient umask.
      box.succeed(
          "install -o ${spec.serviceAccount} -g ${spec.serviceAccount} -m 666"
          " /dev/null ${spec.stateArea}/left-wide-open"
      )

      # The next start REFUSES, and that refusal is the mechanism working rather
      # than a fault: a store file readable by every account is a disclosed
      # credential, so the probe makes it private AND stops, because an operator
      # who is not told cannot find out. Repairing silently would leave the same
      # machine one restart away from the same state with nobody watching.
      box.fail("systemctl restart ${spec.name}.service")
      repaired = box.succeed("journalctl -u ${spec.name}.service --no-pager -o cat | tail -20")
      assert "store_file_shared" in repaired, (
          "a world-readable file in the store did not refuse the start, so the store's privacy "
          "is held by the ambient umask rather than by the service"
      )

      # And the repair really happened, so the second start succeeds. That pair -
      # refuse now, start clean next time - is what makes the refusal actionable
      # rather than a wall an operator has to climb by hand.
      box.succeed("systemctl reset-failed ${spec.name}.service")
      box.succeed("systemctl restart ${spec.name}.service")
      box.wait_for_unit("${spec.name}.service")

      walked = box.succeed(
          "find ${spec.stateArea} -mindepth 1 -printf '%p %U %m\\n'"
      ).strip().splitlines()
      assert walked, (
          "the walk found nothing, so 'every file is private' is true of no file. "
          "The planted file is gone, which means this assertion is measuring nothing."
      )

      # finds every one of them private - mode 0600 or 0700
      #
      # ⚠ NOT "readable by the service account alone", which is what this phrase
      # used to say. The loop below reads the MODE; the owner is read into a
      # variable and never compared, so a root-owned 0600 file in the state area
      # satisfies it. Ownership is asserted separately, on the state directory,
      # where the unit's own `User=` makes it meaningful.
      for entry in walked:
          path, owner, file_mode = entry.rsplit(" ", 2)
          assert file_mode in ("600", "700"), f"{path} is mode {file_mode}, which is readable by somebody else"
    '';
}
