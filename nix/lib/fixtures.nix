# The synthetic credentials every check is driven with, built ONCE from the spec.
#
# THE SHARED LAYER ITSELF (ADR-002). ⚠ THIS FILE IS WHY THE CHECKS ARE PORTABLE
# AT ALL. The reference implementation wrote the same four-line fixture into four
# check files, and each line named a field of ONE consumer's OAuth2 credential:
# `clientIdVariable`, `clientSecretVariable`, `refreshTokenVariable`. Those four
# checks were therefore parameterised by NAME and not by SHAPE - they fit any
# consumer holding exactly an OAuth2 client and a refresh token, and refused
# every consumer that does not. Three of the four named future consumers have no
# OAuth2 grant at all.
#
# So the shape moves into the spec as `credentialsVariables`, an attribute set of
# whatever secrets THIS consumer's credentials file carries, of any size
# including none.
#
# ⚠ ONE OBJECT, SEARCHED AND SUPPLIED. ADR-002 section 4 requires the value the
# closure search looks for and the value the machine is given to be the same
# object: "if the search term and the supplied value are two objects, the search
# proves nothing". That held inside `secret-search.nix` and nowhere else, because
# the other three checks wrote their own copies. Now every check takes both from
# here, so a fixture edited in one place cannot leave a search hunting for a
# value no machine was ever given.
{
  pkgs,
  spec,
}:
let
  # The bearer secret is the SHARED layer's own concept - the module refuses to
  # open a listener without one and the guard compares it - so it is the one
  # credential this file may name.
  sharedSecret = "SYNTHETIC-SHARED-SECRET-3c7a1e9d5b2f4806a7c9e1b3d5f70284";

  # Everything else the consumer's credentials file carries. Empty is a real and
  # supported answer: a server whose only secret is its bearer token supplies
  # nothing here and every check still runs.
  consumerVariables = spec.credentialsVariables or { };

  variables = consumerVariables // {
    "${spec.sharedSecretVariable}" = sharedSecret;
  };

  values = builtins.attrValues variables;

  # ⚠ THE PREFIX IS A GATE, NOT A CONVENTION. This is a PUBLIC repository whose
  # checks plant their fixtures into a real system closure and then grep for
  # them, so the one mistake that would look completely normal here is a real
  # credential arriving as a fixture. It is refused at evaluation.
  notSynthetic = builtins.filter (value: !(pkgs.lib.hasPrefix "SYNTHETIC-" value)) values;

  # Distinctness matters for the same reason the values are long: the closure
  # search asserts that each value is absent, and two identical values would make
  # one of those assertions a restatement of the other rather than a claim.
  distinct = builtins.length (pkgs.lib.unique values) == builtins.length values;

  # A chance substring must not be able to satisfy the search.
  tooShort = builtins.filter (value: builtins.stringLength value < 24) values;
in
assert
  notSynthetic == [ ]
  || throw ''
    REFUSING TO EVALUATE: a credentials fixture does not begin with SYNTHETIC-.

    These values are planted into a real system closure and then searched for, in a PUBLIC
    repository. A fixture that could be mistaken for a real credential is refused here rather
    than reviewed for, because it is the one mistake in this file that would look ordinary.
  '';
assert
  tooShort == [ ]
  || throw ''
    REFUSING TO EVALUATE: a credentials fixture is shorter than 24 characters.

    The closure search asserts these values are ABSENT from a real system. A short value can be
    absent by luck and present by coincidence, and either way the search stops measuring what it
    claims to measure.
  '';
assert
  distinct
  || throw ''
    REFUSING TO EVALUATE: two credentials fixtures have the same value.

    Each value is a separate absence claim against the closure. Two identical values make one of
    those claims a restatement of the other rather than a second measurement.
  '';
{
  inherit sharedSecret variables values;

  #: The credentials file the unit is pointed at. Rendered from the same mapping
  #: the search terms come from.
  file = pkgs.writeText "${spec.name}-synthetic-credentials.env" (
    pkgs.lib.concatStringsSep "\n" (pkgs.lib.mapAttrsToList (name: value: "${name}=${value}") variables) + "\n"
  );
}
