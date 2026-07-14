from __future__ import annotations

import os
from typing import Any

import pytest
from anyio import EndOfStream
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

from lineageguard.config import Settings
from lineageguard.datahub.mcp_client import (
    DataHubMCPClient,
    MCPMissingCapability,
    MCPMutationDisabled,
    MCPToolError,
    _stderr_sink,
)


def _tool(name: str, *, wraps_result: bool = False) -> Tool:
    return Tool(
        name=name,
        inputSchema={"type": "object"},
        outputSchema=(
            {
                "type": "object",
                "properties": {"result": {"type": "array"}},
                "required": ["result"],
                "x-fastmcp-wrap-result": True,
            }
            if wraps_result
            else None
        ),
    )


class FakeSession:
    def __init__(
        self,
        tools: list[str],
        result: CallToolResult | None = None,
        *,
        wrapped_tools: set[str] | None = None,
    ) -> None:
        self.tools = tools
        self.wrapped_tools = wrapped_tools or set()
        self.result = result or CallToolResult(
            content=[TextContent(type="text", text='{"ok": true}')]
        )
        self.initialized = False
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    async def initialize(self) -> object:
        self.initialized = True
        return object()

    async def list_tools(self, cursor: str | None = None) -> ListToolsResult:
        assert cursor is None
        return ListToolsResult(
            tools=[_tool(name, wraps_result=name in self.wrapped_tools) for name in self.tools]
        )

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: object | None = None,
    ) -> CallToolResult:
        self.calls.append((name, arguments))
        return self.result


def _required_tools(*extra: str) -> list[str]:
    return ["search", "get_lineage", "get_entities", "list_schema_fields", *extra]


def test_subprocess_stderr_sink_has_a_real_file_descriptor() -> None:
    with _stderr_sink() as sink:
        assert os.fstat(sink.fileno()).st_mode


@pytest.mark.asyncio
async def test_handshake_requires_core_datahub_tools() -> None:
    session = FakeSession(["search"])
    client = DataHubMCPClient(Settings(_env_file=None), session=session)
    with pytest.raises(MCPMissingCapability, match="get_entities"):
        async with client:
            pass


@pytest.mark.asyncio
async def test_read_call_parses_json_and_records_stable_trace() -> None:
    session = FakeSession(_required_tools())
    client = DataHubMCPClient(Settings(_env_file=None), session=session)
    async with client:
        response = await client.call_read("search", {"query": "orders"})
    assert response.data == {"ok": True}
    assert response.digest == client.trace[0].result_digest
    assert client.trace[0].success is True
    assert session.calls == [("search", {"query": "orders"})]


@pytest.mark.asyncio
async def test_structured_content_takes_precedence() -> None:
    result = CallToolResult(
        content=[TextContent(type="text", text="human rendering")],
        structuredContent={"entities": ["urn:one"]},
    )
    session = FakeSession(_required_tools(), result)
    async with DataHubMCPClient(Settings(_env_file=None), session=session) as client:
        response = await client.call_read("get_entities", {"urns": ["urn:one"]})
    assert response.data == {"entities": ["urn:one"]}
    assert response.text == "human rendering"


@pytest.mark.asyncio
async def test_fastmcp_wrapped_list_is_unwrapped_from_result_metadata() -> None:
    entities = [{"urn": "urn:one"}]
    result = CallToolResult(
        content=[TextContent(type="text", text="human rendering")],
        structuredContent={"result": entities},
        _meta={"fastmcp": {"wrap_result": True}},
    )
    session = FakeSession(_required_tools(), result)
    async with DataHubMCPClient(Settings(_env_file=None), session=session) as client:
        response = await client.call_read("get_entities", {"urns": ["urn:one"]})
    assert response.data == entities


@pytest.mark.asyncio
async def test_fastmcp_wrapped_list_is_unwrapped_from_advertised_schema() -> None:
    entities = [{"urn": "urn:one"}]
    result = CallToolResult(
        content=[TextContent(type="text", text="human rendering")],
        structuredContent={"result": entities},
    )
    session = FakeSession(_required_tools(), result, wrapped_tools={"get_entities"})
    async with DataHubMCPClient(Settings(_env_file=None), session=session) as client:
        response = await client.call_read("get_entities", {"urns": ["urn:one"]})
    assert response.data == entities


@pytest.mark.asyncio
async def test_invalid_fastmcp_wrapper_fails_closed() -> None:
    result = CallToolResult(
        content=[TextContent(type="text", text="human rendering")],
        structuredContent={"entities": [{"urn": "urn:one"}]},
        _meta={"fastmcp": {"wrap_result": True}},
    )
    session = FakeSession(_required_tools(), result)
    async with DataHubMCPClient(Settings(_env_file=None), session=session) as client:
        with pytest.raises(MCPToolError, match="failed after 3 attempt"):
            await client.call_read("get_entities", {"urns": ["urn:one"]})


@pytest.mark.asyncio
async def test_document_capabilities_are_refreshed_after_a_document_is_created() -> None:
    class DynamicDocumentSession(FakeSession):
        def __init__(self) -> None:
            super().__init__(_required_tools())
            self.list_count = 0

        async def list_tools(self, cursor=None):
            assert cursor is None
            self.list_count += 1
            names = self.tools if self.list_count == 1 else [*self.tools, "grep_documents"]
            return ListToolsResult(tools=[_tool(name) for name in names])

    session = DynamicDocumentSession()
    async with DataHubMCPClient(Settings(_env_file=None), session=session) as client:
        response = await client.call_read(
            "grep_documents", {"urns": ["urn:li:document:one"], "pattern": ".*"}
        )

    assert response.data == {"ok": True}
    assert session.list_count == 2


@pytest.mark.asyncio
async def test_acknowledged_save_can_grep_through_cached_document_tool_filter() -> None:
    session = FakeSession(_required_tools("save_document"))
    settings = Settings(_env_file=None, mcp_mutations=True)
    async with DataHubMCPClient(settings, session=session) as client:
        await client.call_mutation("save_document", {"content": "passport"})
        response = await client.call_read(
            "grep_documents", {"urns": ["urn:li:document:one"], "pattern": ".*"}
        )

    assert response.data == {"ok": True}
    assert [name for name, _arguments in session.calls] == [
        "save_document",
        "grep_documents",
    ]


@pytest.mark.asyncio
async def test_hidden_grep_stays_blocked_without_acknowledged_save() -> None:
    session = FakeSession(_required_tools())
    async with DataHubMCPClient(Settings(_env_file=None), session=session) as client:
        with pytest.raises(MCPMissingCapability, match="grep_documents"):
            await client.call_read("grep_documents", {})

    assert session.calls == []


@pytest.mark.asyncio
async def test_mutation_requires_explicit_runtime_enablement() -> None:
    session = FakeSession(_required_tools("add_tags"))
    async with DataHubMCPClient(Settings(_env_file=None), session=session) as client:
        with pytest.raises(MCPMutationDisabled):
            await client.call_mutation("add_tags", {"urns": ["urn:one"]})
    assert session.calls == []


@pytest.mark.asyncio
async def test_mutation_is_not_retried_after_error() -> None:
    result = CallToolResult(content=[TextContent(type="text", text="write failed")], isError=True)
    session = FakeSession(_required_tools("add_tags"), result)
    settings = Settings(_env_file=None, mcp_mutations=True)
    async with DataHubMCPClient(settings, session=session) as client:
        with pytest.raises(MCPToolError, match="after 1 attempt"):
            await client.call_mutation("add_tags", {"urns": ["urn:one"]})
    assert len(session.calls) == 1
    assert len(client.trace) == 1
    assert client.trace[0].success is False


@pytest.mark.asyncio
async def test_unknown_tools_are_rejected_even_if_server_advertises_them() -> None:
    session = FakeSession(_required_tools("run_shell_command"))
    async with DataHubMCPClient(Settings(_env_file=None), session=session) as client:
        with pytest.raises(RuntimeError, match="read allowlist"):
            await client.call_read("run_shell_command", {})


@pytest.mark.asyncio
async def test_transport_failures_are_retried_and_normalized_without_details() -> None:
    class BrokenSession(FakeSession):
        async def call_tool(self, name, arguments=None, read_timeout_seconds=None):
            self.calls.append((name, arguments))
            raise EndOfStream

    session = BrokenSession(_required_tools())
    client = DataHubMCPClient(Settings(_env_file=None), session=session)

    async with client:
        with pytest.raises(MCPToolError, match="failed after 3 attempt") as caught:
            await client.call_read("search", {"query": "orders"})

    assert len(client.trace) == 3
    assert all(event.success is False for event in client.trace)
    assert "EndOfStream" not in str(caught.value)
