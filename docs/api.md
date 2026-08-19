<!-- markdownlint-disable MD013 -->

# The published API

**A change to anything on this page is a breaking change for every consuming
repository.** `checks.api-surface` fails the build when the flake stops exporting
something named here, or starts exporting something that is not.

This page is the reference. The reasoning behind the boundary lives in the
consuming repository's ADR-001 and ADR-002; where this tree and those documents
disagree, [What the ADRs promised and this tree does
not](#what-the-adrs-promised-and-this-tree-does-not) says so explicitly rather
than leaving a reader to find out by grepping.

## `serviceSpec` — one record, read by every factory

A consumer writes this once and passes the same object to `mkServiceModule`,
`mkSessionProbe`, `mkChecks` and `mkFixtures`. Each reads what it needs and
ignores the rest, so a field added for a fourth consumer changes no call site.

### Required

| Field | Type | What it is |
|---|---|---|
| `name` | string | The systemd unit name and the service account name. |
| `description` | string | The unit description, and the option's enable text. |
| `optionPath` | list of string | Where the module's options live, e.g. `[ "services" "example-mcp" ]`. **Explicit, not derived from `name`** — a consumer whose option path differs from its unit name is legitimate, and deriving it silently forbids that. |
| `distributionName` | string | The distribution in the consumer's `uv.lock`, used to version the build output. ⚠ **This row was missing while the page called itself "the whole record"** — a consumer building its spec from it got `called without required argument 'distributionName'`. |
| `consoleScriptName` | string | The one command the wheel installs. |
| `entryPoint` | string | `module:function`. Exactly one; the build refuses a package that does not route through it. Read by `mkServerPackage` as its own argument rather than off the spec — a consumer keeps it in the record because that is where the fact belongs, not because a factory reaches for it there. |
| `stateDirectory` | string | Passed to `StateDirectory=`, so it resolves under `/var/lib`. |
| `stateArea` | string | The absolute path the above resolves to. Derive it — two spellings of one fact that disagree is a unit and a check pointing at different directories. |
| `serviceAccount` | string | The fixed system account. **Not `DynamicUser`** — that moves the state area behind `/var/lib/private/`, so a restart-survival assertion reads a symlink and passes whether or not anything survived. |
| `defaultListenAddress` | string | Usually `127.0.0.1`. Every-interface values are refused at evaluation. |
| `defaultPort` | port | This consumer's port. There is no shared default; see below. |
| `sharedSecretVariable` | string | The name of the bearer secret in the credentials file. |
| `credentialsDirectoryVariable` | string | The variable the unit sets to where systemd put the loaded credential. A **path**, never a secret. |
| `tokenStoreVariable` | string | The variable name the unit sets to `stateArea`, so the server is told where its own state lives. ⚠ **This row was in the Optional table and the module reads it unconditionally** — a consumer following the published API and omitting it died at evaluation with `attribute 'tokenStoreVariable' missing`. Found by an external consumer flake, not by anything in this repository, because the example declares it. |
| `credentialsFileExample` | string | ⚠ **Renders into the option description, which lands in the world-readable Nix store on every build.** It must be unmistakably a placeholder; put the word `example` in the path itself so the file name alone answers the question. |
| `toolNames` | list of string | The surface `mkSessionProbe` reads back BY NAME. Required, not optional: all three VM checks build a probe, so a consumer using `mkChecks` at all must supply it. `mkSessionProbe` **refuses to build on an empty list** — the surface loop is generated from it, so an empty one generates no checks and the probe would report a working surface on any `200`, silently. |
| `meta` | attrs | Standard package meta for the build output. Like `entryPoint`, handed to `mkServerPackage` directly rather than read off the spec. |

### Optional, and each absence is reported rather than assumed

Every field below is read through `spec ? field` or `spec.field or <default>`, so
omitting one is a supported configuration rather than an evaluation error. ⚠ **The
Required table above is the set a consumer must supply** — that
correspondence is the contract, and it was wrong once: `tokenStoreVariable` sat
here while `mkServiceModule` read it directly, so a consumer following this page
and omitting it failed at evaluation.

| Field | Type | What it turns on |
|---|---|---|
| `credentialsVariables` | attrs of string | Every **other** secret this consumer's credentials file carries, as `NAME = "SYNTHETIC-…"`. Default `{ }`, which is a real answer: a server whose only secret is its bearer token supplies nothing and every check still runs. |
| `stateDocument` | `{ name, text }` | The consumer's own persisted document. Turns on the restart-survival, power-cut-survival and unwritable-store scenarios. Absent, each of those **prints a `NOT ASSERTED` line** and the restart and the crash still happen. |
| `upstreamJournalMarker` | string | A string that could only appear in the journal if this server had reached what it integrates with. Turns on one assertion in the deployment check. |

## `lib.mkServerPackage`

```text
{ pkgs, workspaceRoot, distributionName, consoleScriptName, entryPoint,
  pythonGeneration ? "3.12", sourcePreference ? "wheel",
  packagesNeedingSetuptools ? [ ], dependencies ? null, meta }
```

Builds a closed Python environment from `workspaceRoot`'s own `uv.lock`, then
asserts in a `runCommand` that the installed `consoleScriptName` routes through
`entryPoint`. **The assertion is the point** — a flake naming a command reads
identically whether or not the build puts that command anywhere.

`dependencies` is for one case only: a uv **workspace**, where the lock's default
dependency set belongs to the root rather than to the member being built. Pass
`{ <distribution> = [ ]; }`. Every ordinary consumer leaves it null.

## `lib.mkServiceModule`

```text
{ spec } -> a NixOS module
```

**Two guarantees are unconditional behaviour and must never become parameters**,
because leaving their ownership unstated is how a fleet ends up with five copies
of a safety-critical assertion and one of them wrong:

1. **The every-interface refusal.** `0.0.0.0`, `::`, `[::]`, `::0`, `0`, `*` and
   the empty string are refused at evaluation with a message naming the offending
   value and the alternative. Not an `extraAssertion`, not overridable. The empty
   string is on the list because it is the likeliest typo of the lot.
1. **The credentials option type.** It refuses a non-absolute string, and it
   refuses a **Nix path literal** — which is the case that matters: an unquoted
   `./secrets.env` passes `isStringLike` *and* the `/` prefix guard, and the
   module then copies the secrets into the world-readable store. The refusal says
   "put quotation marks round it", and **never repeats the value it was given** —
   a refusal that echoes the offending definition performs a smaller version of
   the leak it is refusing.

The hardening set is spliced with `//` rather than `mkMerge`, so a consumer
cannot weaken a tightening by defining the same directive at a lower priority.

There are **no `extraOptions` / `extraServiceConfig` / `extraEnvironment` /
`extraAssertions` passthroughs.** ADR-002 §3 requires each to name the value it
carries today and to be deleted before publication if it carries none. None
carries one. A passthrough with no consumer is a hole in the boundary rule.

## `lib.mkSessionProbe`

```text
{ pkgs, spec } -> a package installing `<spec.name>-session-probe`
```

A caller that opens a **real** MCP session against a running service and reads the
tool surface back. It reads `spec.name` and `spec.toolNames`, and it takes
`<address> <port> <secret>` on its command line.

It requires, in order: `initialize` to return 200 **and a session id** — something
only a manager with a live task group can mint; `tools/list` to return 200 inside
that session; and **every** name in `spec.toolNames` to be present in the result.

⚠ **It refuses to build on an empty `toolNames`.** The surface loop is generated
from that list, so an empty one generates no checks at all and the probe would
report a working surface on any 200, silently.

⚠ **Why it is this strict.** Every earlier check asked only whether the service
"answers" — that `curl`'s status was not `000`. An HTTP **500 satisfies that**, and
500 is what the server returned to every *authenticated* caller for the whole life
of a branch: the refusal path was asserted precisely and the success path was
asserted as "not nothing", so the guard was proven and the thing it guards was not.

## `lib.mkChecks`

```text
{ pkgs, lib ? pkgs.lib, nixpkgs, system, spec, serverPackage }
  -> { service, deployment, hardening, secret-search }
```

One call, four checks. Importing them one by one — which is what the reference
implementation did — means a consumer can import three, and the one it skips is
invisible: no diff, no refusal, and a repository that ships four checks and runs
three reports green.

`nixpkgs` is the consumer's own flake input; `secret-search` needs `nixosSystem`
because it builds a **real system** rather than a virtual machine.

Three of the four need a builder advertising virtualisation. `secret-search` does
not, and that is deliberate: the check discharging the headline guarantee must
not be gated behind a capability half a fleet lacks.

## `lib.hardening`

Plain data. Two objects in one file:

- `serviceConfig` — the ~28 directives a factory-built unit applies.
- `posture` — `booleanDirectives`, `stringDirectives`, `notTightenings` and
  `required`, in the spellings and values **systemd reports**, measured on a
  running unit rather than taken from the manual.

⚠ **The two halves are independently hand-written and must stay that way.**
Deriving `posture.required` from `serviceConfig` is the change that makes a
deletion invisible: it would leave the expected side and the asked side at once,
and the check would pass. Two assertions in the file keep them honest instead —
a dropped directive and an unreadable-back directive each fail **evaluation**, by
name.

## `lib.mkFixtures`

```text
{ pkgs, spec } -> { sharedSecret, variables, values, file, hostPath, hostModule }
```

`hostPath` and `hostModule` are how a CHECK delivers the fixture: the module
refuses a credentials file named as a store path, so a check that handed it one
would be the least production-like part of the suite. `hostModule` places the
file the way a host does and `hostPath` is what the unit is pointed at.

⚠ **`checks.api-surface` pins the six top-level `lib` names and not the shape of
what they return**, so these two were added and this page went stale for two
commits. If you change what a factory returns, this page is the only thing that
notices.

The synthetic credentials, built once from `spec.sharedSecretVariable` and
`spec.credentialsVariables`. Every check takes both its search terms and its
supplied values from here, which is what makes "the search term and the supplied
value are one object" true across all four rather than inside one.

Refuses at evaluation a value that is not `SYNTHETIC-` prefixed, shorter than 24
characters, or a duplicate of another.

## What the ADRs promised and this tree does not

Written down because the alternative is a reader grepping for a factory that was
never built. Each line is a decision, not an omission.

| Promised | Where | Status here |
|---|---|---|
| `lib/ports.nix`, a fleet port registry | ADR-002 §2 | **Not built, and correctly so.** ADR-007 §2 later rejected it: a map of one operator's services and ports is an operator-specific value, and publishing it falsifies the sentence ADR-001's publication decision rests on. ADR-002 §2 was never amended. |
| The evaluation-time port-collision assertion | ADR-007 §3 | **Not built here.** ADR-007 flags it for the owner's judgement rather than assuming it, because it adds an option to a host's configuration and fleet configuration is out of scope. Batoned as its own lane. |
| `mcp_packaging.contracts`, a `Protocol` for driven adapters | ADR-002 §1 | **Not built.** The reference implementation has no such protocol to move — its ports (`TokenReader` / `TokenWriter`) are its own and stay there. Writing one here would be speculative generality on the component least allowed any. |
| `mcp_packaging.serve` | ADR-002 §1 | **Already present** as `transport.serve_http` / `transport.serve_stdio`. |
| Delete the dead `MCP_PATH` constant | ADR-002 §1 | **Kept, and unreferenced here.** This row used to say an acceptance suite read it; there is no acceptance suite in this repository, and `git grep` finds only its definition. It stays because it is part of the published surface — a consumer writing its own check needs to name the one route — and not because anything here uses it. |
| Collapse the duplicate `TransportKind` / `events.Transport` enums | ADR-002 §1 | **Already one.** The duplicate did not survive into the code this moved from. |
| `checks/version-parity.nix`, `checks/machine-support.nix` | ADR-002 §2 | **Not present in the tree that was moved, and NOT discharged here.** This row used to claim their content lived inside the four checks; it does not — no version comparison and no platform assertion exists in any of them. Two ADR promises with nothing behind them, recorded rather than quietly counted as met. |
| The four checks move "as-is" | ADR-002 §2 | **They could not.** Every one read three named fields that are an OAuth2 grant by construction, and two planted a credential document with a fixed schema. Moved as they stood they would fit only a server holding exactly that grant. Generalised onto `credentialsVariables` and `stateDocument`. |
| A default port in the transport | prior art | **Dropped.** It was one server's port allocation; a shared default hands every other server a port already taken. `port` is a required argument instead. |
| `ProbeCheck` as a closed enum | prior art | **Opened**, exactly as `EventName` already was. `store_corrupt` and `seed_rolled_back` left it — one is about a document only a consumer can parse, the other is one consumer's rotation semantics. |
