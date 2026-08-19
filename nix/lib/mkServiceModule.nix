# The NixOS module factory.
#
# THE SHARED LAYER ITSELF (ADR-002). Nothing here names a consumer's fact -
# everything specific arrives through `spec`. This file arrived here BY MOVE;
# only the hardening table left it, into `lib/hardening.nix`, so the check that
# reads the posture back reads the same object the module applies.
#
# What it produces: a hardened systemd unit running one packaged MCP server on
# its own fixed account, taking its credentials from a runtime file and never
# from a Nix option value, refusing at EVALUATION any configuration that would
# put the service on every interface or a secret in the store.
{
  # One record, read by every factory. See ADR-002 section 3.
  spec,
}:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = lib.getAttrFromPath spec.optionPath config;

  # The tightening set, as data. ONE object, read here and by the hardening
  # check, so the two cannot drift (ADR-002 section 2).
  hardening = import ./hardening.nix;

  # The listen addresses that reach EVERY interface this machine has, in the
  # spellings a person actually types. The first two are the ones an operator
  # reaches for; the rest are the same instruction spelled differently, and a
  # guard catching only the obvious two is a guard that can be walked around by
  # accident. The empty string is in here because it is the likeliest typo of
  # the lot.
  everyInterfaceAddresses = [
    "0.0.0.0"
    "::"
    "[::]"
    "::0"
    "0"
    "*"
    ""
  ];

  # `credentialsFile` names a FILE. It never carries the credential, and it is
  # never a Nix path literal.
  #
  # ⚠ THE PATH-LITERAL CASE IS THE ONE THAT MATTERS AND IT IS NOT HYPOTHETICAL.
  # The reference implementation's equivalent type checks `lib.isStringLike` and
  # then guards on `lib.hasPrefix "/" (toString given)`. A Nix path passes BOTH.
  # Measured on this nixpkgs:
  #
  #   lib.isStringLike ./secrets.env        => true      the check passes
  #   toString ./secrets.env                => /home/... the "/" guard passes
  #   "${./secrets.env}"                    => /nix/store/...-secrets.env
  #
  # So `credentialsFile = ./service.env;` - unquoted, which is the ordinary Nix
  # way to name a file beside the configuration - is ACCEPTED, and the module
  # then interpolates it into the unit, which COPIES THE SECRETS INTO THE STORE.
  # World-readable, permanent, and a later edit does not take it back. The
  # option whose entire purpose is to keep the credential out of the store is
  # the thing that puts it there.
  #
  # The remedy a person needs is "put quotes round it", so the refusal says
  # exactly that. "Invalid value" is not guessable from a missing pair of quotes.
  #
  # And the message never repeats what it was given: a refusal that echoes the
  # offending definition performs a smaller version of the leak it is refusing,
  # into the terminal and into the journal of whatever ran the evaluation.
  credentialsFilePath = lib.mkOptionType {
    name = "credentialsFilePath";
    description = "an absolute path, as a STRING, to a credentials file the host delivers at run time";
    descriptionClass = "noun";
    # ⚠ `check` DELIBERATELY ACCEPTS A PATH, and the refusal happens in `merge`
    # below. This looks backwards and it is load-bearing.
    #
    # Rejecting the path here instead was the first thing I wrote, and it is
    # wrong twice over. `check` returning false never reaches `merge`, so the
    # message naming *quoting* as the remedy became dead code; and the module
    # system's own type error fires in its place, which PRINTS THE OFFENDING
    # DEFINITION. Measured:
    #
    #   error: A definition for option `services.<name>.credentialsFile' is not
    #   of type `...'. Definition values:
    #   - In `...flake.nix': /home/.../treefmt.toml
    #
    # For a credentials file that is a path rather than the secret itself, but
    # the same mechanism echoes whatever it was given - so an operator who
    # mistyped the secret INTO the option has it printed to the terminal and
    # into the journal of whatever ran the evaluation. A refusal that performs a
    # smaller version of the leak it is refusing is not a refusal.
    check = lib.isStringLike;
    merge =
      location: definitions:
      let
        given = lib.mergeEqualOption location definitions;
      in
      if builtins.isPath given then
        throw ''
          REFUSING TO BUILD: ${lib.showOption location} was given a Nix PATH, not a string.

          Put quotation marks round it:

              ${lib.showOption location} = "/run/secrets/${spec.name}.env";

          rather than an unquoted path such as ./${spec.name}.env.

          An unquoted path is COPIED INTO THE NIX STORE when the unit is built, and the
          nix store is world-readable: every account on this machine, and anything that
          can read the store, would hold the credentials for as long as that store path
          exists. Deleting the line afterwards does not take it back.

          This option wants the LOCATION of a file the host delivers at run time. The
          offending value is deliberately not repeated in this message.
        ''
      else if lib.hasPrefix "/" (toString given) then
        given
      else
        throw ''
          REFUSING TO BUILD: ${lib.showOption location} was given a value that is not an absolute path.

          This option accepts only an absolute path to a credentials file - a file the
          host delivers at run time - and never the credential itself.

          A credential written here would be a secret in a nix option value, and nix
          option values are world-readable in the nix store.

          Deliver the credentials with whatever secrets tool this host already uses, and
          name that file here as a quoted absolute path.

          The offending value is deliberately not repeated in this message.
        '';
  };
in
{
  options = lib.setAttrByPath spec.optionPath {
    enable = lib.mkEnableOption "${spec.description} as a managed service";

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = spec.defaultListenAddress;
      example = "192.0.2.10";
      # The deliverable HERE is the text an operator configures against, so the
      # words are the thing rather than a description of it. A document that
      # overstates what protects this service is how somebody binds a tailnet
      # interface believing the address is the control.
      description = ''
        The address the server binds its network transport to. The default
        reaches nothing off this machine.

        a shared secret is required to reach the service
        - every request must carry it, and the server refuses to open a
        listener without one.

        the secret arrives through a file and never through a configuration value
        - an option value is world-readable in the nix store, so a secret
        written as one is published to every account on the machine.

        Widening this address is not the only thing standing between the data
        and whatever can route to it, but it is the control with the widest
        blast radius:
        network reachability is a second control rather than the only one
        - and the existence of the secret is not a reason to widen it.

        The honest residue, which a tidier sentence would drop:
        there is one shared secret, so callers are checked but not told apart
        - anything holding it is the same caller as far as this service is
        concerned.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = spec.defaultPort;
      description = "The port the server binds its network transport to.";
    };

    credentialsFile = lib.mkOption {
      type = credentialsFilePath;
      # spec.credentialsFileExample, never a literal built here (ADR-002 section
      # 3). It renders into the option description, and an option description
      # lands in the nix store on every build - so this is the one example in the
      # module that a person could one day find and be unable to tell from a real
      # value. The consumer owns what its own placeholder looks like, and the ADR
      # requires it to be obviously a placeholder.
      example = spec.credentialsFileExample;
      description = ''
        Path to the file the unit loads its credentials from, written as a
        QUOTED STRING.

        An unquoted Nix path is refused at evaluation, because an unquoted path
        is copied into the world-readable nix store along with everything in it.

        Deliver the file with whatever secrets tool the host already uses; the
        unit only needs it to exist and to be readable by root at start.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      description = "The packaged server this unit runs.";
    };
  };

  config = lib.mkIf cfg.enable {
    # The safe default is half the design, so it is held by a machine rather
    # than by a paragraph in the option documentation. Refused at EVALUATION,
    # before anything is built, because the alternative is a machine that is
    # already reachable by the time anybody reads a warning about it.
    assertions = [
      {
        assertion = !(builtins.elem cfg.listenAddress everyInterfaceAddresses);
        message = ''
          REFUSING TO BUILD: ${
            lib.showOption (spec.optionPath ++ [ "listenAddress" ])
          } is "${cfg.listenAddress}", which reaches every interface this machine has.

          Name a specific interface address instead - the address of the one interface this service should answer on, such as this machine's tailnet address, or the default ${spec.defaultListenAddress} to keep it on this machine alone.

          The shared secret is not a reason to widen it. There is exactly one secret and callers are checked but not told apart, so network reachability is the control that decides who gets to present it at all.
        '';
      }
    ];

    # A FIXED account, not DynamicUser (ADR-008). DynamicUser's account exists
    # only for one unit's lifetime, and it moves the state area behind
    # /var/lib/private/ - so an operator and a check both read a symlink rather
    # than the state, and a restart-survival assertion pointed at the link
    # passes whether or not anything survived.
    users.users.${spec.serviceAccount} = {
      isSystemUser = true;
      group = spec.serviceAccount;
      home = spec.stateArea;
      description = spec.description;
    };
    users.groups.${spec.serviceAccount} = { };

    systemd.services.${spec.name} = {
      inherit (spec) description;
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      serviceConfig = {
        # The unit reports ready only once the listener is bound and accepting.
        # A Type=simple unit would report active the moment the process existed,
        # and anything waiting for it would race its subject.
        Type = "notify";
        NotifyAccess = "main";

        User = spec.serviceAccount;
        Group = spec.serviceAccount;

        # The console script the package's own build asserts is present and
        # routes through the single entry point, so this cannot name a command
        # the package does not ship.
        ExecStart = lib.concatStringsSep " " [
          "${cfg.package}/bin/${spec.consoleScriptName}"
          "--transport http"
          "--host ${cfg.listenAddress}"
          "--port ${toString cfg.port}"
        ];

        # LoadCredential rather than EnvironmentFile (ADR-006). The reference
        # implementation uses EnvironmentFile with a root ExecStartPre presence
        # check, for reasons that hold when every secret is READ-ONLY. This
        # service's credential ROTATES: the seed arrives read-only in this file
        # and the rotated one lives in the state directory, so the two have
        # different lifetimes and must not share a delivery mechanism.
        #
        # It also fails the unit BY ITSELF when the file is absent - systemd
        # refuses to start before ExecStart runs - so there is no presence check
        # to write and no exit code to assert.
        LoadCredential = "${spec.name}:${cfg.credentialsFile}";

        # Where the server finds the credentials systemd just loaded, and where
        # the rotated authorisation is written. Two different lifetimes, two
        # different places, and neither is a Nix value.
        Environment = [
          "${spec.tokenStoreVariable}=${spec.stateArea}"
          "${spec.credentialsDirectoryVariable}=%d/${spec.name}"
        ];

        StateDirectory = spec.stateDirectory;
        WorkingDirectory = spec.stateArea;

        # A transient fault is worth retrying; ten seconds apart so a retrying
        # unit is legible in the journal rather than a wall of restarts. Safe
        # only because every startup refusal is LOCAL and never contacts the
        # vendor - a refusal that reached one would turn this policy into a loop
        # against a token endpoint, which is how a rotating grant dies.
        Restart = "on-failure";
        RestartSec = "10s";
      }
      # ------------------------------------------------------------------
      # The hardening set, applied WHOLE
      # ------------------------------------------------------------------
      # Spliced from `lib/hardening.nix` rather than written out here, and it is
      # the SAME object the hardening check reads its expectations from. The
      # table used to exist twice - here in Nix spelling, and in the check in
      # systemd's rendering - kept in agreement by hand; that file's own
      # assertions are what replaced the hand.
      #
      # `//` and not `lib.mkMerge`: a consumer must not be able to override a
      # tightening by defining the same directive at a lower priority. The
      # posture is this factory's promise to every consumer, not a default.
      // hardening.serviceConfig;

      # A unit nothing can fix by restarting stops trying and stays failed,
      # which an operator can see, rather than flapping, which produces an alert
      # nobody can act on and hides the cause underneath it.
      unitConfig = {
        StartLimitIntervalSec = 300;
        StartLimitBurst = 3;
      };
    };
  };
}
