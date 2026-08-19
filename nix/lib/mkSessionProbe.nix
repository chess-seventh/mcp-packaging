# A caller that opens a real MCP session and reads the tool surface back.
#
# THE SHARED LAYER ITSELF (ADR-002): parameterised, names no consumer's fact.
# The tool names arrive through `spec`.
#
# ⚠ WHY THIS EXISTS, AND IT IS THE SHARPEST LESSON OF THIS LANE. Every check that
# asked whether the service "answers" asserted `curl`'s status was not `000` -
# that is, that something at the far end wrote an HTTP response at all. An HTTP
# **500 satisfies that**, and 500 is exactly what the server did on every
# authenticated request for the whole life of this branch: the session manager's
# task group was never opened, so `handle_request` raised on the first caller who
# HELD the secret.
#
# The shape to remember: the refusal path was asserted precisely (401, and the
# four rejection classes byte-identical), and the SUCCESS path was asserted as
# "not nothing". So the guard was proven and the thing it guards was not, and the
# failure landed only on the callers the guard exists to admit.
#
# So this probe refuses to be satisfied by a response. It requires:
#   1. `initialize` to return 200 AND a session id, because a session id is
#      something only a manager with a live task group can mint;
#   2. `tools/list` to return 200 within that session;
#   3. EVERY expected tool name to be present in the result - the surface, by
#      name, rather than its size, because two tools renamed is a surface that
#      still has two tools in it.
{
  pkgs,
  spec,
}:
# ⚠ REFUSED AT EVALUATION, not at run time. The tool-surface loop below is
# GENERATED from `spec.toolNames`; an empty list generates no checks at all, so
# the probe would report a working surface on any 200 and would do it silently.
# A generated assertion that can generate to nothing is the same shape as an
# assertion over an empty directory, and this repository has met that four times.
assert
  spec.toolNames != [ ]
  || throw ''
    REFUSING TO BUILD: the session probe was given no tool names.

    It reads the tool surface back BY NAME, so an empty list makes it assert
    nothing while still passing - which is worse than not having the probe.
  '';
pkgs.writeShellApplication {
  name = "${spec.name}-session-probe";
  runtimeInputs = [
    pkgs.curl
    pkgs.gnugrep
    pkgs.coreutils
  ];
  text = ''
    set -euo pipefail

    host="$1"
    port="$2"
    secret="$3"
    endpoint="http://$host:$port/mcp"
    auth="Authorization: Bearer $secret"
    accept="Accept: application/json, text/event-stream"
    json="Content-Type: application/json"

    headers="$(mktemp)"
    status="$(
      curl --silent --show-error --dump-header "$headers" --output /dev/null \
        --write-out '%{http_code}' \
        -H "$auth" -H "$json" -H "$accept" \
        -X POST "$endpoint" \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}'
    )"
    if [ "$status" != "200" ]; then
      echo "REFUSING TO REPORT: initialize answered $status, not 200." >&2
      echo "A caller holding the shared secret must be admitted; anything else means the" >&2
      echo "guard is the only half of this transport that works." >&2
      exit 1
    fi

    session="$(grep -i '^mcp-session-id:' "$headers" | tr -d '\r' | cut -d' ' -f2)"
    if [ -z "$session" ]; then
      echo "REFUSING TO REPORT: initialize returned 200 and no session id." >&2
      echo "Only a session manager with a live task group can mint one, so its absence is" >&2
      echo "the difference between a server that answered and one that is merely reachable." >&2
      exit 1
    fi

    curl --silent --show-error --output /dev/null \
      -H "$auth" -H "$json" -H "$accept" -H "mcp-session-id: $session" \
      -X POST "$endpoint" \
      -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

    body="$(mktemp)"
    status="$(
      curl --silent --show-error --output "$body" --write-out '%{http_code}' \
        -H "$auth" -H "$json" -H "$accept" -H "mcp-session-id: $session" \
        -X POST "$endpoint" \
        -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    )"
    if [ "$status" != "200" ]; then
      echo "REFUSING TO REPORT: tools/list answered $status, not 200." >&2
      exit 1
    fi

    missing=""
    ${builtins.concatStringsSep "\n" (
      map (tool: ''
        if ! grep -q '"${tool}"' "$body"; then
          missing="$missing ${tool}"
        fi
      '') spec.toolNames
    )}
    if [ -n "$missing" ]; then
      echo "REFUSING TO REPORT: the tool surface is missing:$missing" >&2
      echo "Asserting the COUNT would have passed here; two tools renamed is still two tools." >&2
      exit 1
    fi

    echo "session opened, tool surface answered by name:${
      builtins.concatStringsSep "" (map (tool: " ${tool}") spec.toolNames)
    }"
  '';
}
