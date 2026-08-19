"""The one MCP ``Server`` object, with the smallest honest tool surface.

ONE object, never copied, which is what makes "the tool surface is identical
whichever way the caller arrives" a fact about the construction rather than a
claim about two lists somebody keeps in agreement.

This server integrates with nothing. That is deliberate: what it exists to prove
is that the shared layer can build, package, harden and check a consumer, and an
upstream would only add a way for the proof to fail for an unrelated reason.
"""

from __future__ import annotations

from typing import Any

from mcp_packaging.events import EventName, emit_event
from mcp_packaging.transport import McpServer

#: The tool surface, read back BY NAME by the session probe. One tool, because
#: the surface is the claim and a longer list does not make it a stronger one.
TOOL_NAMES: tuple[str, ...] = ("ping",)

#: What the one tool answers. A fixed word: this server has no upstream, and a
#: value that looked derived would invite a reader to believe it was.
PONG = "pong"


class UnknownTool(RuntimeError):
    """A tool name this server does not publish.

    An ERROR, not a normal result carrying an ``error`` key: a result would make a
    caller's typo indistinguishable from an answer.

    Deliberately does not repeat the name the caller sent. A caller who reaches
    the socket chooses that string, and echoing it into a message or an event lets
    them mint labels without limit.
    """

    def __init__(self) -> None:
        """Say the tool is not one this server offers, and name nothing else."""
        super().__init__("that is not a tool this server offers")


def build_server() -> McpServer:
    """Build the one MCP ``Server`` object both transports serve.

    Returns:
        The MCP server object.
    """
    from mcp.server import Server
    from mcp.types import TextContent, Tool

    server: Any = Server("example-mcp")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """Publish the declared surface, derived from the one name list."""
        return [
            Tool(
                name=name,
                description="Answer, so a caller can prove it reached this server.",
                inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
            )
            for name in TOOL_NAMES
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[TextContent]:
        """Answer one question, or raise. Never a result carrying an error key."""
        if name not in TOOL_NAMES:
            raise UnknownTool()
        emit_event(EventName.TOOL_CALL, tool=name)
        return [TextContent(type="text", text=PONG)]

    return server
