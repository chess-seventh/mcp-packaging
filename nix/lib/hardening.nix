# The tightening set, as DATA. Plain attribute set, no arguments, no consumer
# facts - the whole file is a constant.
#
# SHARED LAYER (ADR-002 section 2). It exists because the table used to exist
# TWICE: once in the module in Nix spelling, once in the hardening check in
# systemd's rendering, kept in agreement by hand. Two copies of a safety-critical
# list, in two repositories once the layer is published, is the shape that ends
# with every consumer inheriting it and one of them quietly weaker.
#
# ⚠ ONE FILE, TWO INDEPENDENTLY-WRITTEN OBJECTS, AND THAT IS DELIBERATE. A naive
# reading of "the module and the check read one object" would compute `posture`
# from `serviceConfig` - and that destroys the very property the check was
# rewritten to have. The reference check's own header records the measurement:
# a version that derived the expected set from the module was blind to a
# DELETION, because deleting `ProtectClock` removed it from the expected side and
# the asked side at once, and the check stayed at exit 0.
#
# So `serviceConfig` (what is applied) and `posture.required` (what must be
# applied) are two hand-written lists that must AGREE, and the assertions below
# are what makes disagreement impossible to ship:
#
#   * a directive deleted from `serviceConfig` and left in `posture.required`
#     fails EVALUATION, naming it;
#   * a directive added to `serviceConfig` that no posture list knows how to read
#     back fails EVALUATION, naming it.
#
# ⚠ AND THAT IS STRICTLY STRONGER THAN WHERE THIS CAME FROM, for a reason that
# is about the fleet rather than about taste: both questions used to be answered
# only inside a NixOS virtual-machine test, and half the boxes here cannot run
# one. An operator on a box without virtualisation got a green run and no
# completeness bookkeeping at all. Now the bookkeeping fires wherever nix
# evaluates, and the VM check keeps the half only a running unit can answer -
# whether the tightening that is claimed is the tightening that is RUNNING.
let
  # ------------------------------------------------------------------
  # What the factory applies
  # ------------------------------------------------------------------
  # Applied WHOLE, never a selection from it: a directive quietly left out is a
  # weaker posture than the module promises. Where one genuinely costs a service
  # something it is dropped with a recorded exception NEXT TO IT, never omitted
  # silently.
  serviceConfig = {
    # A FIXED account, not DynamicUser (ADR-008). DynamicUser's account exists
    # only for one unit's lifetime and it moves the state area behind
    # /var/lib/private/, so an operator and a check both read a symlink rather
    # than the state - and a restart-survival assertion pointed at the link
    # passes whether or not anything survived.
    DynamicUser = false;
    NoNewPrivileges = true;

    # Empty, not narrowed. A server binding a port above 1024 needs no
    # capability whatever, so the empty set is the correct answer rather than a
    # conservative one.
    CapabilityBoundingSet = "";
    AmbientCapabilities = "";

    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";

    # Nothing beyond StateDirectory. Written out empty on purpose: the day
    # something needs adding here, it is a visible diff.
    ReadWritePaths = [ ];

    # The state area is the service's own and nobody else's. A posture
    # directive, so it lives here rather than beside `StateDirectory` - which is
    # a consumer's fact and stays in the module.
    StateDirectoryMode = "0700";

    # Defence in depth on a store's modes, and explicitly NOT the guarantee -
    # the guarantee is the mode guard in the server, which runs regardless of
    # the ambient mask.
    UMask = "0077";

    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    LockPersonality = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    RestrictNamespaces = true;
    MemoryDenyWriteExecute = true;
    PrivateUsers = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = [
      "@system-service"
      "~@privileged @resources @obsolete @mount @debug @cpu-emulation @swap"
    ];

    # AF_UNIX is NOT optional: dropping it breaks journald logging and the
    # Type=notify readiness datagram, and a unit whose readiness datagram never
    # arrives does not fail fast - it hangs to TimeoutStartSec. AF_NETLINK is
    # the documented addition if name resolution fails, because glibc's
    # getaddrinfo enumerates interfaces over netlink.
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_INET6"
      "AF_UNIX"
    ];
  };

  # ------------------------------------------------------------------
  # What a check must find, read back off the RUNNING unit
  # ------------------------------------------------------------------
  # The property names systemd reports are not always the directive names, and
  # the values are not always the values written. Both were MEASURED on a
  # running unit rather than taken from the manual.
  posture = {
    # Directives systemd answers yes/no about.
    booleanDirectives = [
      "NoNewPrivileges"
      "ProtectHome"
      "PrivateTmp"
      "PrivateDevices"
      "ProtectKernelTunables"
      "ProtectKernelModules"
      "ProtectKernelLogs"
      "ProtectControlGroups"
      "ProtectClock"
      "ProtectHostname"
      "LockPersonality"
      "RestrictRealtime"
      "RestrictSUIDSGID"
      "RestrictNamespaces"
      "MemoryDenyWriteExecute"
      "PrivateUsers"
      "DynamicUser"
    ];

    # Directives whose reported value is a string, with the value systemd
    # reports rather than the value written.
    stringDirectives = {
      ProtectSystem = "strict";
      ProtectProc = "invisible";
      ProcSubset = "pid";
      UMask = "0077";
      SystemCallArchitectures = "native";
      RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX";
      StateDirectoryMode = "0700";
    };

    # Directives a factory-built unit sets that are NOT read back by name.
    #
    # Two different reasons live in this one list, and they are labelled below
    # because a reader cannot tell them apart:
    #
    #   * NOT PART OF THE POSTURE at all - the wiring every unit needs;
    #   * part of the posture but asserted by BEHAVIOUR rather than by string
    #     equality, because systemd reports the empty string for an empty
    #     capability set and that is indistinguishable from "not set".
    notTightenings = [
      # wiring
      "Type"
      "NotifyAccess"
      "User"
      "Group"
      "ExecStart"
      "LoadCredential"
      "Environment"
      "StateDirectory"
      "WorkingDirectory"
      "Restart"
      "RestartSec"
      # posture, asserted by behaviour
      "CapabilityBoundingSet"
      "AmbientCapabilities"
      "SystemCallFilter"
      "ReadWritePaths"
    ];

    # ⚠ THE RECORDED POSTURE. Every directive a factory-built unit must still be
    # setting. Removing a name from here is a deliberate weakening of what every
    # consumer of this layer promises, and it must be as visible in a diff as
    # removing the directive itself.
    #
    # Written out rather than computed, BECAUSE it must not follow its subject:
    # a baseline that moves with the thing it measures records nothing. The
    # assertions below are what keep two hand-written lists honest without
    # letting either derive the other.
    required = [
      "NoNewPrivileges"
      "ProtectHome"
      "PrivateTmp"
      "PrivateDevices"
      "ProtectKernelTunables"
      "ProtectKernelModules"
      "ProtectKernelLogs"
      "ProtectControlGroups"
      "ProtectClock"
      "ProtectHostname"
      "LockPersonality"
      "RestrictRealtime"
      "RestrictSUIDSGID"
      "RestrictNamespaces"
      "MemoryDenyWriteExecute"
      "PrivateUsers"
      "DynamicUser"
      "ProtectSystem"
      "ProtectProc"
      "ProcSubset"
      "UMask"
      "SystemCallArchitectures"
      "RestrictAddressFamilies"
      "StateDirectoryMode"
      "CapabilityBoundingSet"
      "AmbientCapabilities"
      "SystemCallFilter"
      "ReadWritePaths"
    ];
  };

  applied = builtins.attrNames serviceConfig;
  readable =
    posture.booleanDirectives ++ builtins.attrNames posture.stringDirectives ++ posture.notTightenings;

  without = names: from: builtins.filter (name: !(builtins.elem name from)) names;

  # A directive the recorded posture requires and the set no longer applies.
  dropped = without posture.required applied;

  # A tightening applied that no posture list knows how to read back.
  unchecked = without applied readable;
in
assert
  dropped == [ ]
  || throw ''
    REFUSING TO EVALUATE: the hardening set no longer applies ${builtins.toString dropped}, and
    posture.required still names it.

    Dropping a tightening is a weakening of what every consumer of this layer promises. If it is
    deliberate, take the name out of posture.required in the SAME commit, so the diff shows the
    promise changing rather than only the code.
  '';
assert
  unchecked == [ ]
  || throw ''
    REFUSING TO EVALUATE: the hardening set applies ${builtins.toString unchecked}, and no posture
    list says how to read it back off a running unit.

    A tightening nobody checks is a tightening nobody has. Add it to posture.booleanDirectives or
    posture.stringDirectives with the value systemd REPORTS - measured on a running unit, not taken
    from the manual - or to posture.notTightenings if it is wiring rather than posture, and to
    posture.required either way.
  '';
{
  inherit serviceConfig posture;
}
