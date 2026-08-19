{
  description = "mcp-packaging: the shared packaging layer every MCP server in the fleet is built, hardened and checked by (L162)";

  # PUBLIC, and that is a mechanism rather than a preference (ADR-001). A private
  # flake input is unfetchable on this fleet - `access-tokens` is empty, a private
  # reference returns HTTP 404, and there is no SSH key - so a private shared
  # layer would be a shared layer nobody could consume. Publishing is only
  # defensible because nothing here is any operator's: no secret, no port
  # allocation, no host, no health data. Keep it that way and the layer stays
  # publishable; add one fleet fact and it stops being.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-utils.url = "github:numtide/flake-utils";

    # ⚠ CARRIED HERE SO A CONSUMER DOES NOT HAVE TO. ADR-001 promises the later
    # extraction is "a move plus ONE flake-input line per consumer". A consumer
    # forced to declare pyproject-nix, uv2nix and pyproject-build-systems itself -
    # and to keep their `follows` in agreement with this repository's - would be
    # four lines and a standing synchronisation job. `lib.mkServerPackage` closes
    # over these, and takes the consumer's own `pkgs` for everything else.
    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
      ...
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      # ---------------------------------------------------------------------
      # THE CONSUMER SURFACE. This output is the whole point of the repository.
      # ---------------------------------------------------------------------
      # ⚠ IT DID NOT EXIST BEFORE, AND ITS ABSENCE IS WHAT STOPPED THE SECOND
      # CONSUMER. The reference implementation exported `packages`, `checks` and
      # `nixosModules` only; the three factories were reached by relative import
      # (`./nix/lib/mkServerPackage.nix`), which resolves inside that repository
      # and nowhere else. A layer whose factories are unreachable from outside is
      # a layer with one consumer, whatever its files say.
      #
      # NOT per-system: a consumer calls these from wherever it already has a
      # package set. The four that build something take that set as `pkgs`;
      # `mkServiceModule` takes only `spec` and gets `pkgs` from the module
      # system when a host evaluates it, so handing it one is an error.
      #
      # ⚠ THIS COMMENT SAID "every factory takes the consumer's own `pkgs`" and
      # was false about the factory defined twenty lines below it. The README
      # carried the same sentence and was corrected a commit earlier; a claim
      # repeated in two files gets fixed in one.
      mcpPackagingLib = {
        # Build a closed Python environment from the consumer's own uv.lock, and
        # assert the installed console script routes through the declared entry
        # point.
        mkServerPackage =
          args:
          import ./nix/lib/mkServerPackage.nix (
            {
              lib = args.pkgs.lib;
              inherit pyproject-nix uv2nix pyproject-build-systems;
            }
            // args
          );

        # A hardened NixOS service running one packaged MCP server, refusing at
        # EVALUATION any configuration that would put it on every interface or a
        # secret in the store.
        mkServiceModule = args: import ./nix/lib/mkServiceModule.nix args;

        # A caller that opens a REAL MCP session and reads the tool surface back
        # by name. It refuses to be satisfied by an HTTP response.
        mkSessionProbe = args: import ./nix/lib/mkSessionProbe.nix args;

        # All four checks from one call. Importing them one by one is how a
        # consumer ends up running three and reporting green.
        mkChecks = args: import ./nix/lib/mkChecks.nix args;

        # The tightening set as data, for a consumer that writes its own module
        # and still wants this layer's posture. Read-only: the factory applies it
        # unconditionally and a consumer cannot weaken it through this.
        hardening = import ./nix/lib/hardening.nix;

        # The synthetic credentials builder, exposed because a consumer writing a
        # check of its own must use the SAME objects the shared checks search for.
        mkFixtures = args: import ./nix/lib/fixtures.nix args;
      };

      # ---------------------------------------------------------------------
      # THE EXAMPLE CONSUMER - a second SHAPE, not a second copy
      # ---------------------------------------------------------------------
      # Everything below is what a consuming repository writes for itself. It is
      # here so the surface above is exercised from OUTSIDE the layer on every
      # `nix flake check`, by a server whose credential shape is deliberately
      # unlike the reference implementation's: ONE secret, no OAuth grant, and
      # nothing durable to keep.
      exampleSpec = rec {
        name = "example-mcp";
        distributionName = "example-mcp";
        description = "Example MCP server";

        optionPath = [
          "services"
          "example-mcp"
        ];

        consoleScriptName = "example-mcp-server";
        entryPoint = "example_mcp.entrypoint:main";

        stateDirectory = name;
        stateArea = "/var/lib/${stateDirectory}";
        serviceAccount = name;

        defaultListenAddress = "127.0.0.1";

        # An arbitrary high port with no meaning outside this example. A PUBLIC
        # repository must not encode any operator's port plan, so this number is
        # deliberately unrelated to whatever range a real deployment uses.
        defaultPort = 8799;

        tokenStoreVariable = "EXAMPLE_MCP_STATE";
        sharedSecretVariable = "EXAMPLE_MCP_AUTH_TOKEN";
        credentialsDirectoryVariable = "EXAMPLE_MCP_CREDENTIALS_DIR";

        # ⚠ EMPTY, AND THAT IS THE MEASUREMENT. The reference consumer's
        # credentials file carries three further secrets; this one carries none
        # beyond the bearer token. Every check still runs, which is what makes
        # "the checks are parameterised by shape" a fact rather than a claim.
        credentialsVariables = { };

        # ⚠ NEITHER `stateDocument` NOR `upstreamJournalMarker` IS DECLARED, and
        # that is deliberate too: this consumer persists nothing and integrates
        # with nothing, so the checks that would assert those PRINT what they did
        # not assert instead of quietly passing.

        credentialsFileExample = "/run/secrets/${name}.example.env";

        toolNames = [ "ping" ];

        meta = {
          inherit description;
          mainProgram = consoleScriptName;
          platforms = supportedSystems;
          license = nixpkgs.lib.licenses.mit;
        };
      };

      exampleModule = mcpPackagingLib.mkServiceModule { spec = exampleSpec; };
    in
    {
      lib = mcpPackagingLib;

      # The example's module, exported so a reader can evaluate the factory's
      # output without building anything.
      nixosModules.example-mcp = exampleModule;
    }
    // flake-utils.lib.eachSystem supportedSystems (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        examplePackage = mcpPackagingLib.mkServerPackage {
          inherit pkgs;
          workspaceRoot = ./.;
          inherit (exampleSpec)
            distributionName
            consoleScriptName
            entryPoint
            meta
            ;
          # This repository is a uv WORKSPACE, so the lock's default dependency
          # set is the shared layer's own rather than the member's. Named
          # explicitly; see the argument's note in `mkServerPackage.nix`.
          dependencies.example-mcp = [ ];
        };

        exampleChecks = mcpPackagingLib.mkChecks {
          inherit pkgs nixpkgs system;
          spec = exampleSpec;
          serverPackage = examplePackage;
        };
      in
      {
        packages.default = examplePackage;
        packages.example-mcp-server = examplePackage;

        checks = {
          # A repository that ships a factory its checks never run ships a claim
          # rather than an artefact.
          example-server = examplePackage;

          # The published surface is a list that fails the build when it stops
          # being true. Needs no builder feature, so it runs everywhere.
          api-surface = import ./nix/checks/api-surface.nix {
            inherit pkgs;
            inherit (pkgs) lib;
            api = mcpPackagingLib;
          };

          # The Python half, run from the same lock the package is built from.
          unit-tests = import ./nix/checks/unit-tests.nix {
            inherit pkgs;
            inherit (pkgs) lib;
            source = ./.;
          };
        }
        // exampleChecks;
      }
    );
}
