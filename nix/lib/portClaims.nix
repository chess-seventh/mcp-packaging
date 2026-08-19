# The endpoint-claim register: two factory-built MCP services that would bind the
# same address and port on one host fail at EVALUATION rather than at bind.
#
# ADR-007 section 3 specifies the mechanism; it was deliberately not built with
# the rest of the layer because it contributes an option into a HOST's
# configuration, which is fleet-shaped, and that boundary was not this layer's to
# rule on. D-107 ruled it: an internal, non-user-facing option a module
# contributes about ITSELF, read by nothing but this file's own assertion, is
# plumbing inside the shared layer. It never appears in a host's written
# configuration.
#
# What it replaces is weaker and is what exists without it: the second service
# fails to bind when it starts. That refusal is legible - systemd names the unit -
# but it is found on the box, after a deploy, and by the service failing. This
# fires on a laptop during `nixos-rebuild build`.
#
# ⚠ THIS IS NOT `lib/ports.nix`, THE FLEET PORT REGISTRY, WHICH IS STILL
# REJECTED. ADR-007 section 2 refused a map of one operator's services and their
# ports, because such a map is an operator's fact and this repository is public.
# The difference is not a matter of naming: this register holds NOTHING in this
# tree. It is empty here, it is filled at evaluation time by whatever modules a
# host happens to import, and it is read by nothing but the assertion below. It
# publishes no allocation because it contains none - and a rule that reads the
# host's own configuration is also the thing a written registry cannot be, which
# is CORRECT when an operator moves one service onto another's port.
#
# ⚠ IT IS A FILE, AND THAT IS THE WHOLE REASON IT IS ONE. The module system keys
# a module by its path and deduplicates on that key, so N factory-built modules
# importing this path produce ONE instance: one option declaration, and one
# assertion per colliding endpoint. Written inline in `mkServiceModule.nix` the
# same block would be emitted once per module, so a collision between two
# services would print twice and one between three would print three times - the
# same fact, repeated, in the message whose job is to make the collision legible.
{
  config,
  lib,
  ...
}:
let
  claims = config.mcpPackaging.portClaims;

  collisions = lib.filterAttrs (_endpoint: claimants: builtins.length claimants > 1) claims;

  # One claimant, rendered as the lines a reader has to act on: what it is, and
  # the two option paths they can go and change. Naming only the service sends
  # them hunting for where it is configured, and this mechanism exists to remove
  # exactly that hunt.
  #
  # ⚠ SORTED BY SERVICE NAME, because the register's own order is the order the
  # host happened to import its modules in. The same collision described in two
  # different orders on two hosts is a message a reader cannot compare, and
  # nothing about which module was imported first is information.
  claimantLines =
    claimants:
    lib.concatMapStringsSep "\n"
      (claimant: ''
        ${claimant.service}
              ${claimant.portOption} = ${toString claimant.port}
              ${claimant.addressOption} = "${claimant.address}"'')
      (lib.sort (left: right: left.service < right.service) claimants);

  collisionMessage = endpoint: claimants: ''
    REFUSING TO BUILD: PORT ALREADY CLAIMED - ${toString (builtins.length claimants)} services on this host bind ${endpoint}.

    ${claimantLines claimants}

    Two units cannot bind one address and port. Whichever started second would
    fail with EADDRINUSE after the deploy, so this is refused now instead.

    Give one of them a different port, or bind them to different addresses - both
    option paths above are the ones to change. The values shown are the CONFIGURED
    ones, so this fires on a host that moved one service onto another's port just
    as it does on two services that shared a default.
  '';
in
{
  options.mcpPackaging.portClaims = lib.mkOption {
    # Internal and invisible: nothing on a host declares this, nothing reads it
    # but the assertion below, and it must not turn up in the generated options
    # documentation as something an operator could set. That is precisely the
    # property D-107 ruled on - plumbing rather than fleet configuration.
    internal = true;
    visible = false;
    default = { };

    type = lib.types.attrsOf (
      lib.types.listOf (
        lib.types.submodule {
          options = {
            service = lib.mkOption {
              type = lib.types.str;
              description = "The systemd unit claiming this endpoint.";
            };
            address = lib.mkOption {
              type = lib.types.str;
              description = "The configured listen address, whitespace removed.";
            };
            port = lib.mkOption {
              type = lib.types.port;
              description = "The configured port.";
            };
            portOption = lib.mkOption {
              type = lib.types.str;
              description = "The option path a reader changes to move this service's port.";
            };
            addressOption = lib.mkOption {
              type = lib.types.str;
              description = "The option path a reader changes to move this service's address.";
            };
          };
        }
      )
    );

    description = ''
      Every endpoint a factory-built MCP service claims on this host, keyed by
      the configured address and port together and never by the port alone.

      ⚠ KEYED ON BOTH HALVES BECAUSE THE PORT ALONE FIRES ON A CORRECT
      CONFIGURATION. Two services on one port bound to two different addresses -
      loopback and a tailnet address, say - both bind, and a port-keyed register
      would refuse a host that works. A guard that fires on a correct
      configuration is worse than the bind failure it replaces, because it is the
      one an operator learns to work around.

      What that costs is stated rather than implied: two SPELLINGS of one address
      are two keys, so a service on `127.0.0.1` and one on `localhost` collide at
      run time and not here. Nix has no address resolver to close that with, and
      the surrounding module makes the same trade for the same reason - see the
      enumeration note in `mkServiceModule.nix`. This is an accident-catcher.

      A service contributes only while it is enabled: a disabled unit binds
      nothing and claims nothing.
    '';
  };

  # A list that is empty on every host with no collision, so this module costs a
  # correct configuration nothing.
  config.assertions = lib.mapAttrsToList (endpoint: claimants: {
    assertion = false;
    message = collisionMessage endpoint claimants;
  }) collisions;
}
