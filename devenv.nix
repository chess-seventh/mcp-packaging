{
  pkgs,
  ...
}:
let
  # L235 - THE FLEET GATE, as four ordinary hooks of this repository's own
  # (D-115).
  #
  # WHY THIS REPOSITORY NEEDS THEM. `hooks_everywhere.nix` installed the fleet
  # gate on a global `core.hooksPath`, and prek REFUSES to install a
  # repository's own hooks while one points outside the repository - it says so
  # and names the fix. This repository was one of EIGHT that lost its gate to
  # that: `devenv:git-hooks:install` failed, `enterShell` failed with it and
  # `devenv test` returned 1, while `devenv shell -- cmd` still returned 0. Loud
  # in the gate and silent interactively, which is why it went unnoticed.
  #
  # The global value is being removed rather than worked around per repository
  # (Franci, 2026-08-26), and these entries are what replaces it: the gate is
  # reached from inside this repository's own prek run instead of from a config
  # value git obeys. Being one of prek's OWN hooks is the shape that stops
  # fighting a provisioning manager that re-installs on entry - three earlier
  # shapes moved `core.hooksPath` or wrapped prek's shims and each was killed by
  # a reproduction.
  #
  # Built through writeShellApplication so the script is shellchecked at build
  # time and the entries name a store path rather than a working-tree file.
  fleetGateHook = "${
    pkgs.writeShellApplication {
      name = "fleet-gate-hook";
      runtimeInputs = [
        pkgs.coreutils
        pkgs.git
      ];
      text = builtins.readFile ./hooks/fleet-gate-hook;
    }
  }/bin/fleet-gate-hook";
in
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
    # L235 - the fleet gate, reached as four of this repo's own hooks. The
    # rationale is in the `let` block at the top of this file; what matters here
    # is that these four are ordinary entries with nothing special about them.
    fleet-gate = {
      enable = true;
      name = "fleet gate";
      stages = [ "pre-commit" ];
      entry = "${fleetGateHook} pre-commit";
      language = "system";
      pass_filenames = false;
      always_run = true;
    };

    # pass_filenames, because git hands commit-msg the message file and the
    # fleet gate's gitlint and commitizen read it. Getting this wrong lints the
    # wrong thing while still exiting 0.
    fleet-gate-commit-msg = {
      enable = true;
      name = "fleet gate (message)";
      stages = [ "commit-msg" ];
      entry = "${fleetGateHook} commit-msg";
      language = "system";
      pass_filenames = true;
      always_run = true;
    };

    fleet-gate-pre-push = {
      enable = true;
      name = "fleet gate (push)";
      stages = [ "pre-push" ];
      entry = "${fleetGateHook} pre-push";
      language = "system";
      pass_filenames = false;
      always_run = true;
    };

    # The commit diary is hooks_everywhere.nix's post-commit hook - NOT
    # pkgs/git-commit-gate, which ships pre-commit and commit-msg only. On a box
    # with no fleet gate there is no diary, and the entry says so per commit.
    fleet-gate-post-commit = {
      enable = true;
      name = "fleet gate (diary)";
      stages = [ "post-commit" ];
      entry = "${fleetGateHook} post-commit";
      language = "system";
      pass_filenames = false;
      always_run = true;
    };

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
