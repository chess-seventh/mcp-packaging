# example-mcp

The example consumer of [`mcp-packaging`](../../README.md): the smallest honest
MCP server the shared layer can build, package, harden and check.

It exists to be a **second shape**, not a second copy. The reference consumer
(`the reference consumer`) holds an OAuth2 client id, an OAuth2 client secret, a rotating
refresh token and a bearer secret, and it persists a credential document it must
not lose. This one holds **one** secret — the bearer token the shared layer needs
before it will open a listener — and persists nothing.

Until it existed, "the packaging layer is shared" was a claim measured against a
single consumer, and a layer whose shape is decided by one consumer is a guess
about the others.

## What it proves, on every `nix flake check`

- `lib.mkServerPackage` builds it from this repository's own `uv.lock`, and
  asserts the installed `example-mcp-server` routes through the one declared
  entry point.
- `lib.mkServiceModule` turns it into a hardened NixOS service without learning
  a single fact about it beyond its `serviceSpec`.
- `lib.mkChecks` runs all four checks against it — including the two that assert
  restart and power-cut survival, which **print what they did not assert** here
  rather than passing silently, because this consumer declares no
  `stateDocument`.

## Running it by hand

```bash
printf 'EXAMPLE_MCP_AUTH_TOKEN=%s\n' "$(head -c 48 /dev/urandom | base64 | tr -d /+=)" > /tmp/example-mcp.env
chmod 600 /tmp/example-mcp.env
mkdir -p -m 700 /tmp/example-mcp-state

nix run .#example-mcp-server -- \
  --transport http --host 127.0.0.1 --port 8799 \
  --credentials-file /tmp/example-mcp.env --state /tmp/example-mcp-state
```

Then reach it the way the session probe does — `initialize`, a session id, and
`tools/list` inside that session. A bare `curl` without the token gets `401` with
no reason in it, which is the point.
