from __future__ import annotations

import asyncio
import json
import os
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest

import lineageguard.datahub.writeback as writeback_module
from lineageguard.datahub.mcp_client import (
    MCPClientError,
    MCPMissingCapability,
    MCPToolError,
    MCPToolResponse,
)
from lineageguard.datahub.writeback import (
    ChangePassport,
    DataHubWriteback,
    WritebackResult,
    WritebackStatus,
)

SOURCE = "urn:li:dataset:(urn:li:dataPlatform:duckdb,analytics.stg_orders,PROD)"
DOCUMENT = "urn:li:document:lineageguard-change-passport"


def _passport() -> ChangePassport:
    return ChangePassport(
        run_id="run-123",
        source_urn=SOURCE,
        original_risk=96,
        residual_risk=12,
        decision="PASS_WITH_REMEDIATION",
        remediation_status="TESTED",
        evidence_hash="evidence-abc",
        commit_sha="abc123",
        markdown="# Change passport\n\nevidence-abc\n",
    )


class FakeMCP:
    def __init__(
        self,
        *,
        passport: ChangePassport | None = None,
        readback_matches: bool = True,
        fail_tool: str | None = None,
    ) -> None:
        self.passport = passport or _passport()
        self.readback_matches = readback_matches
        self.fail_tool = fail_tool
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        self.saved_content = ""
        self.writeback_state = "PENDING"
        self.decision_tags: set[str] = set()

    async def call_mutation(
        self, tool: str, arguments: dict[str, Any] | None = None
    ) -> MCPToolResponse:
        self.calls.append(("mutation", tool, arguments))
        if self.fail_tool == tool:
            raise MCPToolError("simulated")
        if tool == "add_structured_properties":
            values = (arguments or {}).get("property_values", {})
            state = values.get("urn:li:structuredProperty:io.lineageguard.writebackState")
            if isinstance(state, list) and state:
                self.writeback_state = str(state[0])
        elif tool == "remove_tags":
            self.decision_tags.difference_update((arguments or {}).get("tag_urns", []))
        elif tool == "add_tags":
            self.decision_tags.update((arguments or {}).get("tag_urns", []))
        data: dict[str, Any] = {"success": True}
        if tool == "save_document":
            data["urn"] = DOCUMENT
            self.saved_content = str((arguments or {}).get("content", ""))
        return MCPToolResponse(tool=tool, data=data, text="", digest=f"digest-{tool}")

    async def call_read(
        self, tool: str, arguments: dict[str, Any] | None = None
    ) -> MCPToolResponse:
        self.calls.append(("read", tool, arguments))
        passport = self.passport
        if tool == "search_documents":
            return MCPToolResponse(
                tool=tool,
                data={"searchResults": [], "start": 0, "total": 0},
                text="",
                digest="search-documents",
            )
        if tool == "grep_documents":
            content = self.saved_content or passport.markdown
            return MCPToolResponse(
                tool=tool,
                data={
                    "results": [
                        {
                            "urn": DOCUMENT,
                            "title": f"LineageGuard change passport {passport.run_id}",
                            "matches": [{"excerpt": content, "position": 0}],
                            "total_matches": 1,
                        }
                    ],
                    "total_matches": 1,
                    "documents_with_matches": 1,
                },
                text="",
                digest="grep-document",
            )
        property_values = {
            "runId": passport.run_id,
            "originalRisk": passport.original_risk,
            "residualRisk": passport.residual_risk,
            "decision": passport.decision,
            "remediationStatus": passport.remediation_status,
            "evidenceHash": passport.evidence_hash if self.readback_matches else "wrong",
            "commitSha": passport.commit_sha,
            "writebackState": self.writeback_state,
        }
        source = {
            "urn": SOURCE,
            "structuredProperties": {
                "properties": [
                    {
                        "structuredProperty": {
                            "urn": f"urn:li:structuredProperty:io.lineageguard.{name}"
                        },
                        "values": [
                            (
                                {"numberValue": value}
                                if isinstance(value, int)
                                else {"stringValue": value}
                            )
                        ],
                    }
                    for name, value in property_values.items()
                ]
            },
            "tags": {"tags": [{"tag": {"urn": urn}} for urn in sorted(self.decision_tags)]},
            "relatedDocuments": {
                "start": 0,
                "count": 10,
                "total": 1,
                "documents": [
                    {
                        "urn": DOCUMENT,
                        "type": "DOCUMENT",
                        "info": {"title": f"LineageGuard change passport {passport.run_id}"},
                    }
                ],
            },
        }
        return MCPToolResponse(tool=tool, data=source, text="", digest="readback")


async def _persist_with_journal(
    mcp: Any,
    passport: ChangePassport | None = None,
    **kwargs: Any,
) -> WritebackResult:
    with TemporaryDirectory(prefix="lineageguard-writeback-test-") as temporary:
        return await DataHubWriteback(
            mcp,
            document_index_path=Path(temporary) / "document-index",
            **kwargs,
        ).persist(passport or _passport())


@pytest.mark.asyncio
async def test_writeback_uses_mcp_mutations_then_verifies_readback() -> None:
    mcp = FakeMCP()
    result = await _persist_with_journal(mcp)
    assert result.status is WritebackStatus.VERIFIED
    assert result.document_urn == DOCUMENT
    assert [call[1] for call in mcp.calls] == [
        "search_documents",
        "add_structured_properties",
        "save_document",
        "get_entities",
        "grep_documents",
        "remove_tags",
        "add_tags",
        "get_entities",
        "add_structured_properties",
        "get_entities",
        "grep_documents",
    ]
    property_values = next(
        call[2]["property_values"]
        for call in mcp.calls
        if call[0:2] == ("mutation", "add_structured_properties")
    )
    assert property_values["urn:li:structuredProperty:io.lineageguard.originalRisk"] == [96]
    assert property_values["urn:li:structuredProperty:io.lineageguard.residualRisk"] == [12]
    save_call = next(call for call in mcp.calls if call[1] == "save_document")
    assert save_call[2]["title"] == "LineageGuard change passport run-123"


@pytest.mark.asyncio
async def test_document_creation_without_a_durable_journal_never_calls_save() -> None:
    mcp = FakeMCP()

    first = await DataHubWriteback(mcp).persist(_passport())
    retry = await DataHubWriteback(mcp).persist(_passport())

    assert first.status is WritebackStatus.WRITEBACK_PENDING
    assert retry.status is WritebackStatus.WRITEBACK_PENDING
    assert first.reason == retry.reason == "MCPMissingCapability"
    assert [call[1] for call in mcp.calls].count("save_document") == 0
    assert not any(call[0] == "mutation" for call in mcp.calls)


@pytest.mark.asyncio
async def test_document_index_reuses_verified_document_urn_on_identical_retry(tmp_path) -> None:
    index = tmp_path / "document-index"
    first_mcp = FakeMCP()
    first = await DataHubWriteback(first_mcp, document_index_path=index).persist(_passport())
    assert first.status is WritebackStatus.VERIFIED
    payload = json.loads((index / "run-123.json").read_text(encoding="utf-8"))
    assert payload == {
        "document_urn": DOCUMENT,
        "evidence_hash": "evidence-abc",
        "run_id": "run-123",
        "save_state": "BOUND",
        "schema_version": "1.1",
    }

    retry_mcp = FakeMCP()
    retry_mcp.writeback_state = "VERIFIED"
    retry_mcp.decision_tags = {"urn:li:tag:LineageGuard_PASS_WITH_REMEDIATION"}
    retry = await DataHubWriteback(retry_mcp, document_index_path=index).persist(_passport())

    assert retry.status is WritebackStatus.VERIFIED
    assert [call[1] for call in retry_mcp.calls] == [
        "get_entities",
        "grep_documents",
    ]
    assert retry.mutation_digests == ()


@pytest.mark.asyncio
async def test_legacy_bound_document_pointer_remains_compatible(tmp_path) -> None:
    index = tmp_path / "document-index"
    index.mkdir(mode=0o700)
    pointer = index / "run-123.json"
    pointer.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "run_id": "run-123",
                "evidence_hash": "evidence-abc",
                "document_urn": DOCUMENT,
            }
        ),
        encoding="utf-8",
    )
    pointer.chmod(0o600)
    mcp = FakeMCP()
    mcp.writeback_state = "VERIFIED"
    mcp.decision_tags = {"urn:li:tag:LineageGuard_PASS_WITH_REMEDIATION"}

    result = await DataHubWriteback(mcp, document_index_path=index).persist(_passport())

    assert result.status is WritebackStatus.VERIFIED
    assert [call[1] for call in mcp.calls] == ["get_entities", "grep_documents"]
    assert result.mutation_digests == ()


@pytest.mark.asyncio
async def test_verified_retry_never_replays_a_mutation_that_could_downgrade_state() -> None:
    class MutationRejectingMCP(FakeMCP):
        async def call_mutation(self, tool, arguments=None):
            raise AssertionError(f"verified retry unexpectedly called {tool}")

    mcp = MutationRejectingMCP()
    mcp.writeback_state = "VERIFIED"
    mcp.decision_tags = {"urn:li:tag:LineageGuard_PASS_WITH_REMEDIATION"}

    result = await DataHubWriteback(mcp).persist(replace(_passport(), document_urn=DOCUMENT))

    assert result.status is WritebackStatus.VERIFIED
    assert [call[1] for call in mcp.calls] == ["get_entities", "grep_documents"]
    assert result.mutation_digests == ()


@pytest.mark.asyncio
async def test_corrupt_document_index_fails_pending_before_any_mutation(tmp_path) -> None:
    index = tmp_path / "document-index"
    index.mkdir()
    (index / "run-123.json").write_text("not-json\n", encoding="utf-8")
    mcp = FakeMCP()

    result = await DataHubWriteback(mcp, document_index_path=index).persist(_passport())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert mcp.calls == []


def test_invalid_document_journal_does_not_close_a_transferred_descriptor_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = tmp_path / "document-index"
    index.mkdir(mode=0o700)
    pointer = index / "run-123.json"
    pointer.write_text("not-json\n", encoding="utf-8")
    pointer.chmod(0o600)
    captured: dict[str, int] = {}
    explicitly_closed: list[int] = []
    real_open = writeback_module.os.open
    real_close = writeback_module.os.close

    def tracked_open(path: os.PathLike[str] | str, flags: int, mode: int = 0o777) -> int:
        descriptor = real_open(path, flags, mode)
        if Path(path) == pointer:
            captured["descriptor"] = descriptor
        return descriptor

    def tracked_close(descriptor: int) -> None:
        explicitly_closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(writeback_module.os, "open", tracked_open)
    monkeypatch.setattr(writeback_module.os, "close", tracked_close)
    writer = DataHubWriteback(FakeMCP(), document_index_path=index)

    with pytest.raises(MCPClientError, match="document index is invalid"):
        writer._load_document_journal(_passport())

    assert captured["descriptor"] not in explicitly_closed


def test_failed_document_journal_replace_does_not_close_transferred_descriptor_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = tmp_path / "document-index"
    captured: dict[str, int] = {}
    explicitly_closed: list[int] = []
    real_mkstemp = writeback_module.tempfile.mkstemp
    real_close = writeback_module.os.close

    def tracked_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        descriptor, name = real_mkstemp(*args, **kwargs)
        captured["descriptor"] = descriptor
        return descriptor, name

    def tracked_close(descriptor: int) -> None:
        explicitly_closed.append(descriptor)
        real_close(descriptor)

    def fail_replace(source: object, destination: object) -> None:
        del source, destination
        raise OSError("simulated replace failure")

    monkeypatch.setattr(writeback_module.tempfile, "mkstemp", tracked_mkstemp)
    monkeypatch.setattr(writeback_module.os, "close", tracked_close)
    monkeypatch.setattr(writeback_module.os, "replace", fail_replace)
    writer = DataHubWriteback(FakeMCP(), document_index_path=index)

    with pytest.raises(MCPClientError, match="could not be updated"):
        writer._write_document_journal(
            _passport(),
            save_state="ATTEMPTED",
            document_urn=None,
        )

    assert captured["descriptor"] not in explicitly_closed
    assert list(index.glob("*.json")) == []


@pytest.mark.asyncio
async def test_document_index_keeps_runs_in_independent_pointer_files(tmp_path) -> None:
    index = tmp_path / "document-index"
    first = _passport()
    second = ChangePassport(
        run_id="run-456",
        source_urn=first.source_urn,
        original_risk=first.original_risk,
        residual_risk=first.residual_risk,
        decision=first.decision,
        remediation_status=first.remediation_status,
        evidence_hash="evidence-def",
        commit_sha=first.commit_sha,
        markdown=first.markdown,
    )

    first_result = await DataHubWriteback(FakeMCP(), document_index_path=index).persist(first)
    second_result = await DataHubWriteback(
        FakeMCP(passport=second), document_index_path=index
    ).persist(second)

    assert first_result.status is WritebackStatus.VERIFIED
    assert second_result.status is WritebackStatus.VERIFIED
    assert sorted(path.name for path in index.glob("*.json")) == [
        "run-123.json",
        "run-456.json",
    ]


@pytest.mark.asyncio
async def test_writeback_failure_is_pending_and_never_claims_success() -> None:
    mcp = FakeMCP(fail_tool="save_document")
    result = await _persist_with_journal(mcp)
    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "MCPToolError"
    assert all(call[1] != "get_entities" for call in mcp.calls)


@pytest.mark.asyncio
async def test_ambiguous_save_document_identity_keeps_attempted_journal(tmp_path: Path) -> None:
    class AmbiguousSaveIdentityMCP(FakeMCP):
        async def call_mutation(self, tool, arguments=None):
            response = await super().call_mutation(tool, arguments)
            if tool == "save_document":
                return MCPToolResponse(
                    tool=tool,
                    data={
                        "urn": DOCUMENT,
                        "other": "urn:li:document:unexpected-second-identity",
                    },
                    text="",
                    digest="ambiguous-save",
                )
            return response

    index = tmp_path / "document-index"
    result = await DataHubWriteback(AmbiguousSaveIdentityMCP(), document_index_path=index).persist(
        _passport()
    )

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.document_urn is None
    payload = json.loads((index / "run-123.json").read_text(encoding="utf-8"))
    assert payload["save_state"] == "ATTEMPTED"
    assert payload["document_urn"] is None


@pytest.mark.asyncio
async def test_readback_mismatch_is_pending() -> None:
    result = await _persist_with_journal(FakeMCP(readback_matches=False))
    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "readback_mismatch"


@pytest.mark.asyncio
async def test_document_readback_retries_without_replaying_mutations() -> None:
    identity_attempts = 0

    class ProjectionLagMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            nonlocal identity_attempts
            response = await super().call_read(tool, arguments)
            if (
                tool == "get_entities"
                and self.saved_content
                and not self.decision_tags
                and identity_attempts < 3
            ):
                identity_attempts += 1
                assert isinstance(response.data, dict)
                if identity_attempts < 3:
                    response.data.pop("relatedDocuments", None)
            return response

    mcp = ProjectionLagMCP()
    result = await _persist_with_journal(
        mcp,
        readback_attempts=3,
        readback_retry_delay_seconds=0,
    )

    assert result.status is WritebackStatus.VERIFIED
    assert identity_attempts == 3
    assert [call[1] for call in mcp.calls].count("save_document") == 1
    assert [call[1] for call in mcp.calls].count("add_structured_properties") == 2


@pytest.mark.asyncio
async def test_document_relation_accepts_requested_page_size_larger_than_total() -> None:
    result = await _persist_with_journal(FakeMCP())

    assert result.status is WritebackStatus.VERIFIED


@pytest.mark.asyncio
async def test_document_relation_survives_unhydrated_other_search_hits() -> None:
    class PartiallyHydratedRelationMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_entities":
                assert isinstance(response.data, dict)
                response.data["relatedDocuments"]["total"] = 2
            return response

    result = await _persist_with_journal(PartiallyHydratedRelationMCP())

    assert result.status is WritebackStatus.VERIFIED


@pytest.mark.asyncio
async def test_numeric_readback_accepts_datahub_float_representation() -> None:
    class FloatValueMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool != "get_entities":
                return response
            assert isinstance(response.data, dict)
            for prop in response.data["structuredProperties"]["properties"]:
                for value in prop["values"]:
                    if value.get("numberValue") in {96, 12}:
                        value["numberValue"] = float(value["numberValue"])
            return MCPToolResponse(tool=tool, data=response.data, text="", digest="float-readback")

    result = await _persist_with_journal(FloatValueMCP())

    assert result.status is WritebackStatus.VERIFIED


@pytest.mark.asyncio
async def test_numeric_property_cannot_verify_from_a_string_value() -> None:
    class WrongValueTypeMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_entities":
                assert isinstance(response.data, dict)
                for prop in response.data["structuredProperties"]["properties"]:
                    if prop["structuredProperty"]["urn"].endswith(".originalRisk"):
                        prop["values"] = [{"stringValue": "96"}]
            return response

    result = await _persist_with_journal(WrongValueTypeMCP())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "readback_mismatch"


@pytest.mark.asyncio
async def test_document_values_cannot_substitute_for_missing_source_properties() -> None:
    class EntityBlindnessProbe(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_entities":
                assert isinstance(response.data, dict)
                response.data.pop("structuredProperties", None)
            return response

    result = await _persist_with_journal(EntityBlindnessProbe())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "readback_mismatch"


@pytest.mark.asyncio
async def test_writeback_replaces_stale_mutually_exclusive_decision_tags() -> None:
    mcp = FakeMCP()
    mcp.decision_tags = {
        "urn:li:tag:LineageGuard_BLOCK",
        "urn:li:tag:LineageGuard_REVIEW",
    }

    result = await _persist_with_journal(mcp)

    assert result.status is WritebackStatus.VERIFIED
    assert mcp.decision_tags == {"urn:li:tag:LineageGuard_PASS_WITH_REMEDIATION"}


@pytest.mark.parametrize(
    "entity",
    [
        {
            "globalTags": {"tags": []},
            "tags": {"tags": []},
        },
        {"tags": {"tags": "not-a-list"}},
        {"tags": {"tags": ["not-an-entry"]}},
        {"tags": {"tags": [{"tag": {}}]}},
        {"tags": {"tags": [{"tag": {"urn": "not-a-tag-urn"}}]}},
        {"tags": {"tags": [{"tag": {"urn": "urn:li:tag:bad urn"}}]}},
        {
            "tags": {
                "tags": [
                    {"tag": {"urn": "urn:li:tag:Critical"}},
                    {"tag": {"urn": "urn:li:tag:Critical"}},
                ]
            }
        },
    ],
)
def test_malformed_or_ambiguous_tag_shapes_fail_parsing(entity: dict[str, Any]) -> None:
    assert writeback_module._global_tag_urns(entity) is None


@pytest.mark.asyncio
async def test_conflicting_final_decision_tags_fail_readback() -> None:
    class ConflictingDecisionTagsMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_entities" and self.writeback_state == "VERIFIED":
                assert isinstance(response.data, dict)
                response.data["tags"]["tags"].append(
                    {"tag": {"urn": "urn:li:tag:LineageGuard_BLOCK"}}
                )
            return response

    result = await _persist_with_journal(ConflictingDecisionTagsMCP())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "readback_mismatch"


@pytest.mark.asyncio
async def test_dual_tag_containers_cannot_hide_a_conflict() -> None:
    class DualTagContainersMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_entities":
                assert isinstance(response.data, dict)
                response.data["globalTags"] = {
                    "tags": [
                        {"tag": {"urn": "urn:li:tag:LineageGuard_BLOCK"}},
                    ]
                }
            return response

    result = await _persist_with_journal(DualTagContainersMCP())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "readback_mismatch"


@pytest.mark.asyncio
async def test_conflicting_structured_property_value_fails_readback() -> None:
    class ConflictingValueMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_entities":
                assert isinstance(response.data, dict)
                for prop in response.data["structuredProperties"]["properties"]:
                    urn = prop["structuredProperty"]["urn"]
                    if urn.endswith(".decision"):
                        prop["values"].append({"stringValue": "BLOCK"})
            return response

    result = await _persist_with_journal(ConflictingValueMCP())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "readback_mismatch"


@pytest.mark.asyncio
async def test_duplicate_structured_property_urn_cannot_hide_a_conflict() -> None:
    class DuplicatePropertyMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_entities":
                assert isinstance(response.data, dict)
                properties = response.data["structuredProperties"]["properties"]
                decision = next(
                    entry
                    for entry in properties
                    if entry["structuredProperty"]["urn"].endswith(".decision")
                )
                properties.insert(
                    0,
                    {
                        "structuredProperty": dict(decision["structuredProperty"]),
                        "values": [{"stringValue": "BLOCK"}],
                    },
                )
            return response

    result = await _persist_with_journal(DuplicatePropertyMCP())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "readback_mismatch"


@pytest.mark.parametrize(
    "malformed_entry",
    [
        {"structuredProperty": {"urn": "not-a-structured-property-urn"}, "values": []},
        {"structuredProperty": {"urn": "urn:li:structuredProperty:bad urn"}, "values": []},
        {"structuredProperty": {"urn": "urn:li:structuredProperty:io.lineageguard.unexpected"}},
        "not-an-entry",
    ],
)
@pytest.mark.asyncio
async def test_malformed_structured_property_entry_fails_readback(malformed_entry) -> None:
    class MalformedPropertyMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_entities":
                assert isinstance(response.data, dict)
                response.data["structuredProperties"]["properties"].append(malformed_entry)
            return response

    result = await _persist_with_journal(MalformedPropertyMCP())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "readback_mismatch"


@pytest.mark.asyncio
async def test_tag_is_read_back_while_state_is_pending_before_verified_mutation() -> None:
    mcp = FakeMCP()

    result = await _persist_with_journal(mcp)

    assert result.status is WritebackStatus.VERIFIED
    add_tag_index = next(index for index, call in enumerate(mcp.calls) if call[1] == "add_tags")
    verified_index = next(
        index
        for index, call in enumerate(mcp.calls)
        if call[1] == "add_structured_properties"
        and call[2]["property_values"].get(
            "urn:li:structuredProperty:io.lineageguard.writebackState"
        )
        == ["VERIFIED"]
    )
    assert mcp.calls[add_tag_index + 1][0:2] == ("read", "get_entities")
    assert add_tag_index < verified_index


@pytest.mark.asyncio
async def test_save_document_cannot_rebind_a_verified_pointer() -> None:
    alternate = "urn:li:document:different"

    class RebindingMCP(FakeMCP):
        async def call_mutation(self, tool, arguments=None):
            response = await super().call_mutation(tool, arguments)
            if tool == "save_document":
                return MCPToolResponse(
                    tool=tool,
                    data={"success": True, "urn": alternate},
                    text="",
                    digest="rebound",
                )
            return response

    passport = replace(_passport(), document_urn=DOCUMENT)
    result = await DataHubWriteback(RebindingMCP()).persist(passport)

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.document_urn == DOCUMENT
    assert result.reason == "readback_mismatch"


@pytest.mark.asyncio
async def test_document_index_root_file_fails_pending_without_calls(tmp_path) -> None:
    index = tmp_path / "document-index"
    index.write_text("not-a-directory\n", encoding="utf-8")
    mcp = FakeMCP()

    result = await DataHubWriteback(mcp, document_index_path=index).persist(_passport())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "MCPClientError"
    assert mcp.calls == []


@pytest.mark.parametrize(
    "updates",
    [
        {"run_id": 'bad" query'},
        {"source_urn": "urn:li:dashboard:wrong"},
        {"decision": "INVENTED"},
        {"original_risk": 101},
        {"evidence_hash": "contains a space"},
        {"markdown": ""},
        {"markdown": "\ud800"},
        {"document_urn": "not-a-document"},
    ],
)
@pytest.mark.asyncio
async def test_unsafe_passport_identity_fails_before_any_mcp_call(updates) -> None:
    mcp = FakeMCP()

    result = await DataHubWriteback(mcp).persist(replace(_passport(), **updates))

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert mcp.calls == []


@pytest.mark.asyncio
async def test_pointer_with_non_private_mode_fails_before_mcp_calls(tmp_path) -> None:
    index = tmp_path / "document-index"
    index.mkdir(mode=0o700)
    pointer = index / "run-123.json"
    pointer.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "run_id": "run-123",
                "evidence_hash": "evidence-abc",
                "document_urn": DOCUMENT,
            }
        ),
        encoding="utf-8",
    )
    pointer.chmod(0o644)
    mcp = FakeMCP()

    result = await DataHubWriteback(mcp, document_index_path=index).persist(_passport())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert mcp.calls == []


@pytest.mark.asyncio
async def test_unknown_document_index_schema_fails_pending_without_calls(tmp_path) -> None:
    index = tmp_path / "document-index"
    index.mkdir(mode=0o700)
    pointer = index / "run-123.json"
    pointer.write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "run_id": "run-123",
                "evidence_hash": "evidence-abc",
                "document_urn": DOCUMENT,
            }
        ),
        encoding="utf-8",
    )
    pointer.chmod(0o600)
    mcp = FakeMCP()

    result = await DataHubWriteback(mcp, document_index_path=index).persist(_passport())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert mcp.calls == []


@pytest.mark.asyncio
async def test_same_run_concurrent_writeback_is_single_writer(tmp_path) -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    class BlockingMCP(FakeMCP):
        async def call_mutation(self, tool, arguments=None):
            if tool == "add_structured_properties" and not started.is_set():
                started.set()
                await release.wait()
            return await super().call_mutation(tool, arguments)

    index = tmp_path / "document-index"
    first_mcp = BlockingMCP()
    first_task = asyncio.create_task(
        DataHubWriteback(first_mcp, document_index_path=index).persist(_passport())
    )
    await started.wait()
    second_mcp = FakeMCP()
    second = await DataHubWriteback(second_mcp, document_index_path=index).persist(_passport())
    release.set()
    first = await first_task

    assert first.status is WritebackStatus.VERIFIED
    assert second.status is WritebackStatus.WRITEBACK_PENDING
    assert second_mcp.calls == []


@pytest.mark.asyncio
async def test_missing_pointer_recovers_exact_remote_document_before_save(tmp_path) -> None:
    class RecoveringMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "search_documents":
                self.calls.append(("read", tool, arguments))
                passport = self.passport
                return MCPToolResponse(
                    tool=tool,
                    data={
                        "searchResults": [
                            {
                                "entity": {
                                    "urn": DOCUMENT,
                                    "info": {
                                        "title": (f"LineageGuard change passport {passport.run_id}")
                                    },
                                }
                            }
                        ],
                        "start": 0,
                        "total": 1,
                    },
                    text="",
                    digest="recover-search",
                )
            return await super().call_read(tool, arguments)

    index = tmp_path / "document-index"
    mcp = RecoveringMCP()

    result = await DataHubWriteback(mcp, document_index_path=index).persist(_passport())

    assert result.status is WritebackStatus.VERIFIED
    save = next(call for call in mcp.calls if call[1] == "save_document")
    assert save[2]["urn"] == DOCUMENT
    assert (index / "run-123.json").is_file()


@pytest.mark.asyncio
async def test_lost_save_response_is_never_replayed_without_recovery_capability(tmp_path) -> None:
    class LostResponseMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "search_documents":
                self.calls.append(("read", tool, arguments))
                raise MCPMissingCapability("search_documents is unavailable")
            return await super().call_read(tool, arguments)

        async def call_mutation(self, tool, arguments=None):
            response = await super().call_mutation(tool, arguments)
            if tool == "save_document":
                raise MCPToolError("response was lost after the save committed")
            return response

    index = tmp_path / "document-index"
    mcp = LostResponseMCP()

    first = await DataHubWriteback(mcp, document_index_path=index).persist(_passport())
    retry = await DataHubWriteback(mcp, document_index_path=index).persist(_passport())

    assert first.status is WritebackStatus.WRITEBACK_PENDING
    assert retry.status is WritebackStatus.WRITEBACK_PENDING
    assert [call[1] for call in mcp.calls].count("save_document") == 1
    payload = json.loads((index / "run-123.json").read_text(encoding="utf-8"))
    assert payload == {
        "document_urn": None,
        "evidence_hash": "evidence-abc",
        "run_id": "run-123",
        "save_state": "ATTEMPTED",
        "schema_version": "1.1",
    }


@pytest.mark.asyncio
async def test_empty_document_recovery_accepts_omitted_search_results() -> None:
    class EmptyDocumentSearchMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "search_documents":
                self.calls.append(("read", tool, arguments))
                return MCPToolResponse(
                    tool=tool,
                    data={"count": 50, "start": 0, "total": 0},
                    text="",
                    digest="empty-search",
                )
            return await super().call_read(tool, arguments)

    mcp = EmptyDocumentSearchMCP()
    result = await _persist_with_journal(mcp)

    assert result.status is WritebackStatus.VERIFIED
    assert [call[1] for call in mcp.calls].count("save_document") == 1


@pytest.mark.asyncio
async def test_ambiguous_remote_document_recovery_fails_before_mutation() -> None:
    class AmbiguousRecoveryMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "search_documents":
                self.calls.append(("read", tool, arguments))
                title = f"LineageGuard change passport {self.passport.run_id}"
                return MCPToolResponse(
                    tool=tool,
                    data={
                        "searchResults": [
                            {"entity": {"urn": DOCUMENT, "info": {"title": title}}},
                            {
                                "entity": {
                                    "urn": "urn:li:document:duplicate",
                                    "info": {"title": title},
                                }
                            },
                        ],
                        "start": 0,
                        "total": 2,
                    },
                    text="",
                    digest="ambiguous-search",
                )
            return await super().call_read(tool, arguments)

    mcp = AmbiguousRecoveryMCP()
    result = await DataHubWriteback(mcp).persist(_passport())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "readback_mismatch"
    assert all(call[0] == "read" for call in mcp.calls)


@pytest.mark.asyncio
async def test_malformed_remote_document_search_fails_before_mutation() -> None:
    class MalformedRecoveryMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            if tool == "search_documents":
                self.calls.append(("read", tool, arguments))
                return MCPToolResponse(
                    tool=tool,
                    data={"searchResults": [], "start": 4, "total": 0},
                    text="",
                    digest="malformed-search",
                )
            return await super().call_read(tool, arguments)

    mcp = MalformedRecoveryMCP()
    result = await DataHubWriteback(mcp).persist(_passport())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert all(call[0] == "read" for call in mcp.calls)


@pytest.mark.asyncio
async def test_document_relation_can_be_proved_inside_a_truncated_window() -> None:
    class TruncatedRelationMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_entities":
                assert isinstance(response.data, dict)
                relation = response.data["relatedDocuments"]
                relation["count"] = 10
                relation["total"] = 11
                relation["documents"].extend(
                    {
                        "urn": f"urn:li:document:other-{index}",
                        "type": "DOCUMENT",
                        "info": {"title": f"Other document {index}"},
                    }
                    for index in range(9)
                )
            return response

    result = await _persist_with_journal(TruncatedRelationMCP())

    assert result.status is WritebackStatus.VERIFIED


@pytest.mark.asyncio
async def test_document_relation_missing_from_truncated_window_fails_closed() -> None:
    class MissingTruncatedRelationMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "get_entities":
                assert isinstance(response.data, dict)
                response.data["relatedDocuments"] = {
                    "start": 0,
                    "count": 10,
                    "total": 11,
                    "documents": [
                        {
                            "urn": f"urn:li:document:another-{index}",
                            "type": "DOCUMENT",
                            "info": {"title": f"Another document {index}"},
                        }
                        for index in range(10)
                    ],
                }
            return response

    result = await _persist_with_journal(MissingTruncatedRelationMCP())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "readback_mismatch"


@pytest.mark.asyncio
async def test_document_content_mismatch_fails_closed() -> None:
    class WrongDocumentMCP(FakeMCP):
        async def call_read(self, tool, arguments=None):
            response = await super().call_read(tool, arguments)
            if tool == "grep_documents":
                assert isinstance(response.data, dict)
                response.data["results"][0]["matches"][0]["excerpt"] = "wrong"
            return response

    result = await _persist_with_journal(WrongDocumentMCP())

    assert result.status is WritebackStatus.WRITEBACK_PENDING
    assert result.reason == "readback_mismatch"
