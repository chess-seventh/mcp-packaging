# mcp-packaging

The shared packaging layer for a fleet of MCP servers: the Python components and
the Nix factories that turn one server into a **build output**, a **hardened
NixOS service**, and a **set of checks that can fail**.

It is deliberately small and deliberately ignorant. It knows about MCP servers,
sockets, headers, systemd units, Nix derivations and filesystem modes. It knows
nothing about any integration, nor about the data one holds.

> **If a domain concept ever needs to enter this layer, that is the signal the
> abstraction is wrong, not a reason to widen it.**

That single rule is enforced rather than asserted — see [The boundary, and what
holds it](#the-boundary-and-what-holds-it).

## Why it is public

A private flake input is unfetchable on the fleet this serves: `access-tokens` is
empty, a private reference returns HTTP 404, and there is no SSH key. A private
shared layer would be a shared layer nobody could consume.

Publishing is only defensible because nothing here belongs to any operator — no
secret, no port allocation, no host, no health data. Every credential-shaped
string in the tree is a `SYNTHETIC-` prefixed fixture that exists to be searched
*for*, and `nix/lib/fixtures.nix` refuses at evaluation any that is not.

## What a consumer gets

```nix
{
  inputs.mcp-packaging.url = "github:chess-seventh/mcp-packaging";
}
```

One input line. `pyproject-nix`, `uv2nix` and `pyproject-build-systems` are
carried here, so a consumer does not declare them or keep their `follows` in
agreement with this repository's.

| Export | What it is |
|---|---|
| `lib.mkServerPackage` | A closed Python environment resolved from the consumer's own `uv.lock`, with the installed console script **asserted at build time** to route through the one declared entry point. |
| `lib.mkServiceModule` | A NixOS module factory. Produces a hardened unit on a fixed account, taking credentials from a runtime file and never from a Nix option value. |
| `lib.mkSessionProbe` | A caller that opens a **real** MCP session, requires a session id, and reads every expected tool back by name. It refuses to be satisfied by an HTTP response. |
| `lib.mkChecks` | All four checks from one call — service, deployment, hardening, and the closure secret search. |
| `lib.hardening` | The tightening set as data: `serviceConfig` (what is applied) and `posture` (what must be applied). |
| `lib.mkFixtures` | The synthetic credentials builder, for a consumer writing a check of its own. |

None of these is per-system: a consumer calls them from wherever it already has
a package set. The four that build something take that set as `pkgs`;
`mkServiceModule` takes only `spec` and gets `pkgs` from the module system when
the host evaluates it, so passing it one is an error rather than a no-op.

The full parameter surface is [`docs/api.md`](docs/api.md). The shape of a
consumer is [`examples/example-mcp`](examples/example-mcp/README.md), and it is
built and checked here on every run rather than described.

## One `serviceSpec`, read by every factory

A consumer writes **one** record and passes the same object to the four
factories that take one, which read what they need and ignore the rest. That is what reduces
what a new consumer must get right from about forty arguments to one object, and
what makes a field added for a fourth consumer change no call site.

```nix
serviceSpec = rec {
  name = "example-mcp";
  optionPath = [ "services" "example-mcp" ];
  consoleScriptName = "example-mcp-server";
  entryPoint = "example_mcp.entrypoint:main";
  sharedSecretVariable = "EXAMPLE_MCP_AUTH_TOKEN";
  credentialsVariables = { };   # every OTHER secret this server's file carries
  # ... see docs/api.md for the whole record
};
```

## The boundary, and what holds it

An architecture rule without a mechanism is a wish. Five of them here:

| Layer | Mechanism | The question it answers |
|---|---|---|
| Naming | `tests/unit/test_boundary.py` over every published file **and every published path** | "does anything here name another server in this family?" |
| Address | the same file, over every published file except the two lock files | "does anything name a machine outside this repository — by URL, by bare hostname, or by IP — or a port in the range these servers run in?" |
| Dependency | the same file asks a **fresh interpreter** what one import costs | "does importing this drag in an MCP server or an HTTP client?" |
| Surface | `checks.api-surface` | "does every symbol the published API names exist, and is anything exported that it does not name?" |
| Posture | `nix/lib/hardening.nix` asserts at **evaluation** | "has a tightening been dropped, or added without anything able to read it back?" |

The naming rule matches by **shape** — any `<something>-mcp` that is not this
repository's own — rather than against a list of servers, so it holds for a
consumer nobody has written yet and it publishes no roster.

**What it deliberately does not do, because it cannot:** there is no rule for a
vendor name written on its own, with no `-mcp` suffix. To catch one, a rule must
know the word, and any representation of "this exact word is forbidden" that
lives in a public tree can be read back. A salted SHA-256 was tried and is no
better than a plain list — the salt sits beside it, the words are short and
ordinary, and a reviewer recovered every one from a hand-typed candidate list in
under a minute. A false claim about a disclosure is worse than the disclosure, so
the rule was removed rather than dressed up. Bare names are caught **before**
publication instead: by review, and by the redaction pass that rewrites this
branch's history before its first push.

The two lock files are exempt from the *address* rules and from nothing else. A
lock file is a machine-written record of where its own dependencies came from, so
it carries registry addresses by construction; a consumer's name cannot arrive in
one by hand, and the naming rules still read them.

**Three further limits, stated rather than implied.** The hostname rule knows a
long but finite list of top-level domains, so a host under one it does not know
passes. The rules read ASCII: a homoglyph, a unicode hyphen or a base64 blob
carrying a name passes. And they are accident-catchers, not adversary-catchers —
somebody determined to smuggle a string past them can.

Nothing scans **commit messages**. The current history is clean and was checked,
but no rule keeps it so — that belongs to a hook, not to a unit test.

**Posture** is worth naming, because it moved: it used to live only inside a
NixOS virtual-machine test, and half the boxes in this fleet cannot run one — so
on those, the completeness bookkeeping never ran at all. It now runs wherever
`nix` evaluates, and the VM check keeps the half only a running unit can answer.

(This paragraph names its subject because it once did not. Two paragraphs were
inserted above it and "the last one" quietly came to mean the sentence about
commit messages, asserting the opposite of what that sentence says.)

## Running the checks

```bash
nix flake check                  # everything below
nix build .#checks.x86_64-linux.example-server # the example consumer builds at all
nix build .#checks.x86_64-linux.unit-tests     # the Python suite, no VM, seconds
nix build .#checks.x86_64-linux.api-surface    # the published API, no VM, instant
nix build .#checks.x86_64-linux.build-system-hook # the escape hatch stays general, evaluation only
nix build .#checks.x86_64-linux.port-claims    # the endpoint guard, no VM, evaluation only
nix build .#checks.x86_64-linux.secret-search  # a real system closure, no VM
nix build .#checks.x86_64-linux.service        # NixOS VM test  (needs KVM)
nix build .#checks.x86_64-linux.deployment     # NixOS VM test  (needs KVM)
nix build .#checks.x86_64-linux.hardening      # NixOS VM test  (needs KVM)
```

### What the checks here do not reach

Said out loud rather than left for a consumer to discover:

- ⚠ **This bullet used to say no repository outside this tree consumes the flake,
  and that the first consuming repository would be the first to walk the input
  path. One has, and the path was broken.** A consuming repository took the input
  on 2026-08-19 and could not build: consumed as a **git source** — the only route
  an external repository has — this layer has neither an sdist nor a wheel entry
  in a consumer's lock, so nothing said what to build it with, and no argument
  the published API offered could say. L185 is that fix
  (`packagesNeedingBuildSystems`). `examples/example-mcp` never met it because it
  resolves as a uv **workspace** member, which is not a route any other
  repository can take — so the export stays proven by the example, and the input
  path is now proven by a second repository building against this flake over the
  network. That repository is deliberately not named here — the naming rule below
  is the reason, and it applies to this bullet as much as to any other line.
- The **`stateDocument` branch** of the service and deployment checks — restart
  survival, power-cut survival, and the unwritable-store node — is neither run
  nor **evaluated** here, because the example consumer persists nothing and Nix
  does not evaluate the arm it did not take. This paragraph claimed it was
  evaluated; it is not, and the difference is the whole guard: a typo inside
  those blocks stays green here and surfaces in the first consumer that declares
  a `stateDocument`. Each skip prints a `NOT ASSERTED` line naming itself.
- The closure secret search runs against **one** secret here, not the several a
  consumer with a full credentials file supplies.
- `nix flake check` is run for `x86_64-linux`; `aarch64-linux` is declared
  supported and is not built on this hardware.

**Three of the eight need a builder advertising virtualisation** and will not run
on a box without `/dev/kvm`. That is why the closure secret search — the check
that discharges the headline claim — is deliberately *not* a VM test, and why the
unit suite runs on a bare interpreter.

## Developing

The development shell is `devenv`, and every tool the gate uses comes from it —
never from the host:

```bash
devenv shell -- tests        # pytest
devenv shell -- lint         # ruff
devenv shell -- typecheck    # ty
devenv shell -- fmt          # treefmt over the whole tree
```

`uv.lock` is a **workspace** lock covering both this package and the example
consumer. Regenerate it with `devenv shell -- uv lock` after changing either
`pyproject.toml`.

There is deliberately no `.env` and no `dotenv` in the shell. This layer holds no
credential of its own, and an environment file here would be a credential surface
on the one component that must not have one.

## What is deliberately NOT here

Each of these was considered and rejected with a reason, and the reasons are what
keep the layer small:

- **A durable atomic write.** The reference implementation's is truncate-in-place
  with no `fsync`. Publishing it as "the fleet's durable write" would give every
  consumer a durability guarantee it does not have. Its *lock* and its *mode
  enforcement* did move, as `mcp_packaging.store_modes`; its write did not.
- **`private_umask`.** Umask-plus-chmod is the weaker mechanism this design
  replaces with mode-from-the-creating-syscall. Publishing it would offer four
  consumers the mechanism the design rejected.
- **A fleet port registry.** A map of one operator's services and ports is an
  operator-specific value, and this repository is public. A consumer passes
  `defaultPort`; the registry, if wanted, belongs to whatever repository owns
  fleet configuration. **What is here instead is strictly better and publishes
  nothing:** every factory-built module contributes the address and port it
  *actually resolved to* into an internal register, and two services claiming one
  endpoint on a host fail at evaluation. It reads the configured value, so it
  catches an operator moving one service onto another's port — which a written
  registry cannot — and it holds no allocation of its own, because it is empty
  until a host fills it.
- **A generic OAuth2 client.** One consumer needs one, which is not a shared
  layer — it is a wrapper or a framework, and either breaks the boundary rule on
  the first commit.
- **`credentialDelivery` and `hardeningOverrides`.** Two credential mechanisms in
  a security-relevant shared layer is real surface for a migration its own record
  calls cheap; an escape hatch on the hardening table has no consumer at all.

## Licence

MIT. See [LICENSE](LICENSE).
