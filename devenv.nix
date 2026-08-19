{
  pkgs,
  ...
}:
{
  # The development shell. It is NOT how anything here is deployed - this
  # repository ships a library and a set of Nix factories, and a consumer's own
  # flake is what builds a service out of them. This shell exists to run the
  # tests and the formatters.
  #
  # ⚠ NO `dotenv`, and its absence is deliberate. The reference consumer enables
  # it to read an OAuth client secret locally; this layer holds no credential of
  # its own, so an environment file here would be a credential surface on the one
  # component that must not have one.

  delta.enable = true;

  # 3.12, matching the interpreter `lib.mkServerPackage` defaults to. The two are
  # written down in both places on purpose and must agree: a lock file can
  # resolve a dependency differently per interpreter generation, so a suite run
  # against one interpreter proves nothing about a package built against another.
  languages.python = {
    enable = true;
    version = "3.12";

    venv.enable = true;

    uv = {
      enable = true;
      package = pkgs.uv;
      sync.enable = true;
    };
  };

  packages = with pkgs; [
    # Code quality. ruff alone - no black, no isort. ruff-format supersedes
    # black and ruff's `I` rules supersede isort, and running either pair over
    # the same buffer is two formatters competing for it.
    ruff
    ty

    # Secret scanning. Every fixture in this repository is a SYNTHETIC- prefixed
    # value that exists to be searched FOR, so a real one arriving by accident is
    # exactly the mistake that would look normal here.
    gitleaks

    # Utilities
    git
    jq
    curl
  ];

  git-hooks.hooks = {
    check-merge-conflicts = {
      name = "Check merge conflicts";
      enable = true;
      stages = [ "pre-commit" ];
    };
    detect-private-keys = {
      name = "Detect private keys";
      enable = true;
      stages = [ "pre-commit" ];
    };
    end-of-file-fixer = {
      name = "End of file fixer";
      enable = true;
      stages = [ "pre-commit" ];
    };
    mixed-line-endings = {
      name = "Mixed line endings";
      enable = true;
      stages = [ "pre-commit" ];
    };
    trim-trailing-whitespace = {
      name = "Trim trailing whitespace";
      enable = true;
      stages = [ "pre-commit" ];
    };

    treefmt = {
      name = "treefmt";
      enable = true;
      settings.formatters = [
        pkgs.nixfmt
        pkgs.deadnix
        pkgs.yamlfmt
        pkgs.ruff
        pkgs.toml-sort
        pkgs.mdformat
      ];
      stages = [ "pre-commit" ];
    };

    gitlint = {
      name = "gitlint";
      enable = true;
    };

    # ⚠ THE PINNED ty, NEVER `nix run nixpkgs#ty`. The two are different
    # versions: the registry channel's tool is whatever that box last pulled,
    # this one is the flake input every other check already uses. When the hook
    # and the script disagreed, the script reported clean while the gate did not.
    ty = {
      name = "Type check (ty)";
      enable = true;
      entry = "${pkgs.ty}/bin/ty check src";
      language = "system";
      types = [ "python" ];
      pass_filenames = false;
      stages = [ "pre-commit" ];
    };

    gitleaks = {
      name = "Detect secrets (gitleaks)";
      enable = true;
      entry = "${pkgs.gitleaks}/bin/gitleaks git --staged --redact --no-banner";
      language = "system";
      pass_filenames = false;
      always_run = true;
      stages = [ "pre-commit" ];
    };
  };

  scripts = {
    tests = {
      description = "Run the test suite";
      exec = "uv run pytest \"$@\"";
    };
    # ONE ruff and ONE ty, the same ones the pre-commit hook and treefmt run.
    lint = {
      description = "Lint with ruff";
      exec = "${pkgs.ruff}/bin/ruff check src tests \"$@\"";
    };
    typecheck = {
      description = "Type-check the shipped package";
      exec = "${pkgs.ty}/bin/ty check src";
    };
    fmt = {
      description = "Format the whole tree";
      exec = "${pkgs.treefmt}/bin/treefmt \"$@\"";
    };
  };
}
