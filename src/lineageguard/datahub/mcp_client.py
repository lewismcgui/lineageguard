"""Fail-closed client for DataHub's official self-hosted MCP server."""

from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import time
from collections.abc import Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol, Self, TextIO, cast

from anyio import BrokenResourceError, ClosedResourceError, EndOfStream
from mcp import ClientSession, McpError, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

from lineageguard.config import Settings

READ_TOOLS = frozenset(
    {
        "search",
        "get_lineage",
        "get_lineage_paths_between",
        "get_entities",
        "list_schema_fields",
        "get_dataset_queries",
        "search_documents",
        "grep_documents",
    }
)
REQUIRED_READ_TOOLS = frozenset({"search", "get_lineage", "get_entities", "list_schema_fields"})
MUTATION_TOOLS = frozenset(
    {
        "add_tags",
        "remove_tags",
        "add_structured_properties",
        "save_document",
    }
)


class MCPSession(Protocol):
    """Subset of the MCP client session used by LineageGuard."""

    async def initialize(self) -> Any: ...

    async def list_tools(self, cursor: str | None = None) -> ListToolsResult: ...

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> CallToolResult: ...


class MCPClientError(RuntimeError):
    """Base exception for an unavailable or invalid MCP interaction."""


class MCPMissingCapability(MCPClientError):
    """The connected server does not expose a required tool."""


class MCPMutationDisabled(MCPClientError):
    """A mutation was attempted without explicit run-time enablement."""


class MCPToolError(MCPClientError):
    """The MCP tool returned an error or an invalid result."""


@dataclass(frozen=True, slots=True)
class ToolCapability:
    """Server-advertised schema retained for validation and evidence."""

    name: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any] | None
    wraps_result: bool
    read_only_hint: bool | None


@dataclass(frozen=True, slots=True)
class MCPToolResponse:
    """Normalized MCP response plus a stable evidence digest."""

    tool: str
    data: Mapping[str, Any] | list[Any] | str | int | float | bool | None
    text: str
    digest: str


@dataclass(frozen=True, slots=True)
class MCPTraceEvent:
    """Secret-free call trace used by the evidence ledger and demo UI."""

    tool: str
    argument_digest: str
    result_digest: str | None
    duration_ms: int
    success: bool
    attempt: int


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _stderr_sink() -> TextIO:
    """Return a real file descriptor for AnyIO's subprocess stderr target."""

    return tempfile.TemporaryFile(mode="w+", encoding="utf-8")


def _normalize_result(
    result: CallToolResult, tool: str, *, schema_wraps_result: bool = False
) -> MCPToolResponse:
    if result.isError:
        message = "\n".join(item.text for item in result.content if isinstance(item, TextContent))
        raise MCPToolError(f"DataHub MCP tool {tool!r} failed: {message or 'unknown error'}")

    text = "\n".join(item.text for item in result.content if isinstance(item, TextContent))
    data: Mapping[str, Any] | list[Any] | str | int | float | bool | None
    if result.structuredContent is not None:
        fastmcp = result.meta.get("fastmcp") if isinstance(result.meta, Mapping) else None
        metadata_wraps_result = (
            fastmcp.get("wrap_result") is True if isinstance(fastmcp, Mapping) else False
        )
        if schema_wraps_result or metadata_wraps_result:
            if set(result.structuredContent) != {"result"}:
                raise MCPToolError(
                    f"DataHub MCP tool {tool!r} returned invalid wrapped structured content"
                )
            unwrapped = result.structuredContent["result"]
            if (
                isinstance(unwrapped, Mapping | list | str | int | float | bool)
                or unwrapped is None
            ):
                data = unwrapped
            else:  # pragma: no cover - MCP JSON values are exhausted above
                raise MCPToolError(f"DataHub MCP tool {tool!r} returned a non-JSON wrapped result")
        else:
            data = result.structuredContent
    elif schema_wraps_result:
        raise MCPToolError(f"DataHub MCP tool {tool!r} omitted its advertised structured result")
    elif text:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            data = text
        else:
            if isinstance(parsed, Mapping | list | str | int | float | bool) or parsed is None:
                data = parsed
            else:  # pragma: no cover - json values are exhausted above
                data = str(parsed)
    else:
        data = None
    return MCPToolResponse(tool=tool, data=data, text=text, digest=_canonical_digest(data))


class DataHubMCPClient:
    """Capability-aware MCP client that never silently downgrades DataHub usage."""

    def __init__(self, settings: Settings, *, session: MCPSession | None = None) -> None:
        self.settings = settings
        self._injected_session = session
        self._session: MCPSession | None = session
        self._stack: AsyncExitStack | None = None
        self._stderr: TextIO | None = None
        self._capabilities: dict[str, ToolCapability] = {}
        self._trace: list[MCPTraceEvent] = []
        self._acknowledged_document_save = False

    @property
    def capabilities(self) -> Mapping[str, ToolCapability]:
        return dict(self._capabilities)

    @property
    def trace(self) -> tuple[MCPTraceEvent, ...]:
        return tuple(self._trace)

    async def __aenter__(self) -> Self:
        if self._session is None:
            if self.settings.resolve_datahub_token() is None:
                raise MCPClientError(
                    "A DataHub token is required for the self-hosted DataHub MCP server"
                )
            self._stack = AsyncExitStack()
            try:
                self._stderr = _stderr_sink()
                params = StdioServerParameters(
                    command=self.settings.mcp_command,
                    args=list(self.settings.mcp_args),
                    env=self.settings.mcp_environment(),
                    cwd=self.settings.project_root,
                )
                read_stream, write_stream = await self._stack.enter_async_context(
                    stdio_client(params, errlog=self._stderr)
                )
                session = ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=timedelta(seconds=self.settings.mcp_timeout_seconds),
                )
                connected_session = await self._stack.enter_async_context(session)
                self._session = cast(MCPSession, connected_session)
            except BaseException:
                await self._close_stack()
                raise

        try:
            async with asyncio.timeout(self.settings.mcp_timeout_seconds):
                await self._require_session().initialize()
                await self._discover_capabilities()
        except TimeoutError as exc:
            await self._close_stack()
            raise MCPClientError("Timed out starting the DataHub MCP server") from exc
        except (OSError, McpError, EndOfStream, BrokenResourceError, ClosedResourceError) as exc:
            await self._close_stack()
            raise MCPClientError("Failed to start the DataHub MCP server") from exc
        except BaseException:
            await self._close_stack()
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        await self._close_stack()

    async def _close_stack(self) -> None:
        if self._stack is not None:
            stack, self._stack = self._stack, None
            await stack.aclose()
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None
        if self._injected_session is None:
            self._session = None

    def _require_session(self) -> MCPSession:
        if self._session is None:
            raise MCPClientError("DataHub MCP client is not connected")
        return self._session

    async def _discover_capabilities(self) -> None:
        cursor: str | None = None
        capabilities: dict[str, ToolCapability] = {}
        for _page in range(20):
            result = await self._require_session().list_tools(cursor=cursor)
            for tool in result.tools:
                capabilities[tool.name] = self._to_capability(tool)
            cursor = result.nextCursor
            if cursor is None:
                break
        else:
            raise MCPClientError("MCP tool discovery exceeded the 20-page safety limit")

        self._capabilities = capabilities
        self.require_tools(REQUIRED_READ_TOOLS)

    @staticmethod
    def _to_capability(tool: Tool) -> ToolCapability:
        hint = tool.annotations.readOnlyHint if tool.annotations is not None else None
        output_schema = tool.outputSchema
        return ToolCapability(
            name=tool.name,
            input_schema=tool.inputSchema,
            output_schema=output_schema,
            wraps_result=(
                output_schema.get("x-fastmcp-wrap-result") is True
                if isinstance(output_schema, Mapping)
                else False
            ),
            read_only_hint=hint,
        )

    def require_tools(self, names: set[str] | frozenset[str]) -> None:
        missing = sorted(set(names) - self._capabilities.keys())
        if missing:
            raise MCPMissingCapability(
                "DataHub MCP server is missing required tools: " + ", ".join(missing)
            )

    async def call_read(
        self, tool: str, arguments: Mapping[str, Any] | None = None
    ) -> MCPToolResponse:
        if tool not in READ_TOOLS:
            raise MCPClientError(f"Tool {tool!r} is not in LineageGuard's read allowlist")
        allow_hidden_grep = (
            tool == "grep_documents"
            and self._acknowledged_document_save
            and tool not in self._capabilities
        )
        if (
            tool in {"search_documents", "grep_documents"}
            and tool not in self._capabilities
            and not allow_hidden_grep
        ):
            # The official server dynamically hides document reads until the
            # catalog has a Document. Refresh once in case another client has
            # created one since the handshake.
            await self._discover_capabilities()
        return await self._call(
            tool,
            arguments,
            attempts=self.settings.mcp_max_read_attempts,
            mutation=False,
            allow_unadvertised=allow_hidden_grep,
        )

    async def call_mutation(
        self, tool: str, arguments: Mapping[str, Any] | None = None
    ) -> MCPToolResponse:
        if tool not in MUTATION_TOOLS:
            raise MCPClientError(f"Tool {tool!r} is not in LineageGuard's mutation allowlist")
        if not self.settings.mcp_mutations:
            raise MCPMutationDisabled(
                "MCP mutations are disabled; explicitly enable write-back for this run"
            )
        response = await self._call(tool, arguments, attempts=1, mutation=True)
        if tool == "save_document":
            # DataHub MCP 0.6.0 caches the document-free tool list for 60
            # seconds even though call_tool can immediately serve grep_documents.
            # Only a successful save unlocks that single hidden read below.
            self._acknowledged_document_save = True
        return response

    async def _call(
        self,
        tool: str,
        arguments: Mapping[str, Any] | None,
        *,
        attempts: int,
        mutation: bool,
        allow_unadvertised: bool = False,
    ) -> MCPToolResponse:
        if not allow_unadvertised:
            self.require_tools({tool})
        safe_arguments = dict(arguments or {})
        argument_digest = _canonical_digest(safe_arguments)
        last_error: BaseException | None = None

        for attempt in range(1, attempts + 1):
            started = time.monotonic()
            try:
                async with asyncio.timeout(self.settings.mcp_timeout_seconds):
                    result = await self._require_session().call_tool(
                        tool,
                        safe_arguments,
                        read_timeout_seconds=timedelta(seconds=self.settings.mcp_timeout_seconds),
                    )
                response = _normalize_result(
                    result,
                    tool,
                    schema_wraps_result=(
                        self._capabilities[tool].wraps_result
                        if tool in self._capabilities
                        else False
                    ),
                )
            except (
                TimeoutError,
                OSError,
                McpError,
                EndOfStream,
                BrokenResourceError,
                ClosedResourceError,
                MCPToolError,
            ) as exc:
                last_error = exc
                self._trace.append(
                    MCPTraceEvent(
                        tool=tool,
                        argument_digest=argument_digest,
                        result_digest=None,
                        duration_ms=round((time.monotonic() - started) * 1000),
                        success=False,
                        attempt=attempt,
                    )
                )
                if mutation or attempt == attempts:
                    break
                await asyncio.sleep(min(0.25 * (2 ** (attempt - 1)), 1.0))
            else:
                self._trace.append(
                    MCPTraceEvent(
                        tool=tool,
                        argument_digest=argument_digest,
                        result_digest=response.digest,
                        duration_ms=round((time.monotonic() - started) * 1000),
                        success=True,
                        attempt=attempt,
                    )
                )
                return response

        assert last_error is not None
        kind = "mutation" if mutation else "read"
        raise MCPToolError(
            f"DataHub MCP {kind} tool {tool!r} failed after {attempts} attempt(s)"
        ) from last_error
