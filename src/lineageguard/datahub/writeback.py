"""Persist a LineageGuard change passport through official DataHub MCP mutations."""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from lineageguard.datahub.mcp_client import (
    MCPClientError,
    MCPMissingCapability,
    MCPToolResponse,
)

PROPERTY_PREFIX = "urn:li:structuredProperty:io.lineageguard."
_STRUCTURED_PROPERTY_URN = re.compile(r"^urn:li:structuredProperty:[^\s\x00-\x1f\x7f]+$")
_TAG_URN = re.compile(r"^urn:li:tag:[^\s\x00-\x1f\x7f]+$")
_DOCUMENT_URN = re.compile(r"^urn:li:document:[^\s\x00-\x1f\x7f]+$")
DECISION_TAGS = frozenset(
    {
        "urn:li:tag:LineageGuard_PASS",
        "urn:li:tag:LineageGuard_PASS_WITH_REMEDIATION",
        "urn:li:tag:LineageGuard_REVIEW",
        "urn:li:tag:LineageGuard_BLOCK",
    }
)
# The document relation is search-backed and can trail a successful mutation
# by an index refresh. Retry only reads; never replay the mutations.
DOCUMENT_PROJECTION_READBACK_ATTEMPTS = 5
DOCUMENT_PROJECTION_RETRY_DELAY_SECONDS = 4.0


class MCPWriter(Protocol):
    async def call_mutation(
        self, tool: str, arguments: dict[str, Any] | None = None
    ) -> MCPToolResponse: ...

    async def call_read(
        self, tool: str, arguments: dict[str, Any] | None = None
    ) -> MCPToolResponse: ...


class WritebackStatus(StrEnum):
    VERIFIED = "VERIFIED"
    WRITEBACK_PENDING = "WRITEBACK_PENDING"


class _ReadbackMismatch(MCPClientError):
    """A read succeeded but did not prove the entity-bound state."""


@dataclass(frozen=True, slots=True)
class ChangePassport:
    run_id: str
    source_urn: str
    original_risk: int
    residual_risk: int
    decision: str
    remediation_status: str
    evidence_hash: str
    commit_sha: str
    markdown: str
    document_urn: str | None = None


@dataclass(frozen=True, slots=True)
class WritebackResult:
    status: WritebackStatus
    document_urn: str | None
    mutation_digests: tuple[str, ...]
    readback_digests: tuple[str, ...]
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class _DocumentJournalEntry:
    save_state: str
    document_urn: str | None


def _scalars(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            found.add(str(key))
            found.update(_scalars(nested))
    elif isinstance(value, list | tuple):
        for nested in value:
            found.update(_scalars(nested))
    elif value is not None:
        found.add(str(value))
    return found


def _extract_document_urn(response: MCPToolResponse) -> str | None:
    matches = {
        scalar for scalar in _scalars(response.data) if _DOCUMENT_URN.fullmatch(scalar) is not None
    }
    return next(iter(matches)) if len(matches) == 1 else None


def _is_exact_number(values: set[tuple[str, str]], expected: int) -> bool:
    if len(values) != 1:
        return False
    value_type, scalar = next(iter(values))
    if value_type != "numberValue":
        return False
    try:
        return Decimal(scalar) == Decimal(expected)
    except InvalidOperation:
        return False


def _entities_by_urn(data: object) -> dict[str, Mapping[str, Any]]:
    if isinstance(data, Mapping):
        values: list[object] = [data]
    elif isinstance(data, list):
        values = data
    else:
        return {}
    entities: dict[str, Mapping[str, Any]] = {}
    for item in values:
        if not isinstance(item, Mapping):
            return {}
        urn = item.get("urn")
        if not isinstance(urn, str) or urn in entities or item.get("error") is not None:
            return {}
        entities[urn] = item
    return entities


def _structured_property_values(
    entity: Mapping[str, Any],
) -> dict[str, set[tuple[str, str]]] | None:
    container = entity.get("structuredProperties")
    entries = container.get("properties") if isinstance(container, Mapping) else None
    if not isinstance(entries, list):
        return None
    properties: dict[str, set[tuple[str, str]]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            return None
        definition = entry.get("structuredProperty")
        urn = definition.get("urn") if isinstance(definition, Mapping) else None
        values = entry.get("values")
        if (
            not isinstance(urn, str)
            or _STRUCTURED_PROPERTY_URN.fullmatch(urn) is None
            or urn in properties
            or not isinstance(values, list)
        ):
            return None
        observed: set[tuple[str, str]] = set()
        for value in values:
            if not isinstance(value, Mapping):
                return None
            populated = [
                key
                for key in ("stringValue", "numberValue")
                if key in value and value[key] is not None
            ]
            if len(populated) != 1:
                return None
            key = populated[0]
            scalar = value[key]
            if key == "stringValue":
                if not isinstance(scalar, str):
                    return None
            elif isinstance(scalar, bool) or not isinstance(scalar, int | float):
                return None
            typed_value = (key, str(scalar))
            if typed_value in observed:
                return None
            observed.add(typed_value)
        properties[urn] = observed
    return properties


def _global_tag_urns(entity: Mapping[str, Any]) -> set[str] | None:
    present = [name for name in ("globalTags", "tags") if name in entity]
    if not present:
        return set()
    if len(present) != 1:
        return None
    container = entity.get(present[0])
    entries = container.get("tags") if isinstance(container, Mapping) else None
    if not isinstance(entries, list):
        return None
    urns: set[str] = set()
    for entry in entries:
        tag = entry.get("tag") if isinstance(entry, Mapping) else None
        urn = tag.get("urn") if isinstance(tag, Mapping) else None
        if not isinstance(urn, str) or _TAG_URN.fullmatch(urn) is None or urn in urns:
            return None
        urns.add(urn)
    return urns


def _related_document_matches(
    source: Mapping[str, Any], passport: ChangePassport, document_urn: str
) -> bool:
    related = source.get("relatedDocuments")
    if not isinstance(related, Mapping):
        return False
    start = related.get("start")
    count = related.get("count")
    total = related.get("total")
    documents = related.get("documents")
    if (
        start != 0
        or not isinstance(count, int)
        or isinstance(count, bool)
        or not isinstance(total, int)
        or isinstance(total, bool)
        # DataHub's RelatedDocumentsResult.count is the requested page size,
        # not the number of returned documents. The pinned MCP always requests
        # ten, so a valid short first page can be count=10, total=1, len=1.
        or count != 10
        or total < 0
        or not isinstance(documents, list)
        # Core can omit search hits that fail entity hydration. A returned
        # exact document still proves the relation, but the page must never
        # contain more items than its search arithmetic permits.
        or len(documents) > min(total, count)
    ):
        return False
    observed: dict[str, str] = {}
    for item in documents:
        if not isinstance(item, Mapping):
            return False
        urn = item.get("urn")
        info = item.get("info")
        title = info.get("title") if isinstance(info, Mapping) else None
        if not isinstance(urn, str) or not isinstance(title, str) or urn in observed:
            return False
        observed[urn] = title
    return observed.get(document_urn) == f"LineageGuard change passport {passport.run_id}"


def _grep_document_matches(data: object, passport: ChangePassport, document_urn: str) -> bool:
    if not isinstance(data, Mapping):
        return False
    results = data.get("results")
    if (
        data.get("documents_with_matches") != 1
        or data.get("total_matches") != 1
        or not isinstance(results, list)
        or len(results) != 1
    ):
        return False
    result = results[0]
    if not isinstance(result, Mapping):
        return False
    matches = result.get("matches")
    if (
        result.get("urn") != document_urn
        or result.get("title") != f"LineageGuard change passport {passport.run_id}"
        or result.get("total_matches") != 1
        or not isinstance(matches, list)
        or len(matches) != 1
    ):
        return False
    match = matches[0]
    return (
        isinstance(match, Mapping)
        and match.get("position") == 0
        and match.get("excerpt") == passport.markdown
    )


def _source_matches(
    source: Mapping[str, Any],
    passport: ChangePassport,
    *,
    writeback_state: str,
    tag: bool | None,
) -> bool:
    expected_properties = {
        f"{PROPERTY_PREFIX}runId": passport.run_id,
        f"{PROPERTY_PREFIX}decision": passport.decision,
        f"{PROPERTY_PREFIX}remediationStatus": passport.remediation_status,
        f"{PROPERTY_PREFIX}evidenceHash": passport.evidence_hash,
        f"{PROPERTY_PREFIX}commitSha": passport.commit_sha,
        f"{PROPERTY_PREFIX}writebackState": writeback_state,
    }
    observed_properties = _structured_property_values(source)
    if observed_properties is None:
        return False
    strings_match = all(
        observed_properties.get(property_urn, set()) == {("stringValue", expected)}
        for property_urn, expected in expected_properties.items()
    )
    scores_match = _is_exact_number(
        observed_properties.get(f"{PROPERTY_PREFIX}originalRisk", set()),
        passport.original_risk,
    ) and _is_exact_number(
        observed_properties.get(f"{PROPERTY_PREFIX}residualRisk", set()),
        passport.residual_risk,
    )
    observed_tags = _global_tag_urns(source)
    if observed_tags is None:
        return False
    expected_tag = f"urn:li:tag:LineageGuard_{passport.decision}"
    if tag is True:
        tags_match = observed_tags.intersection(DECISION_TAGS) == {expected_tag}
    elif tag is False:
        tags_match = not observed_tags.intersection(DECISION_TAGS)
    else:
        tags_match = True
    return strings_match and scores_match and tags_match


class DataHubWriteback:
    """Write then read back machine and human change state through MCP."""

    def __init__(
        self,
        mcp: MCPWriter,
        *,
        document_index_path: Path | None = None,
        readback_attempts: int = 1,
        readback_retry_delay_seconds: float = 0.0,
    ) -> None:
        if readback_attempts < 1:
            raise ValueError("readback attempts must be positive")
        if readback_retry_delay_seconds < 0:
            raise ValueError("readback retry delay must not be negative")
        self.mcp = mcp
        self.document_index_path = document_index_path
        self.readback_attempts = readback_attempts
        self.readback_retry_delay_seconds = readback_retry_delay_seconds

    @staticmethod
    def _validate_passport(passport: ChangePassport) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", passport.run_id):
            raise MCPClientError("change passport run ID is invalid")
        if not passport.source_urn.startswith("urn:li:dataset:"):
            raise MCPClientError("change passport source is not a dataset URN")
        if passport.decision not in {"PASS", "PASS_WITH_REMEDIATION", "REVIEW", "BLOCK"}:
            raise MCPClientError("change passport decision is invalid")
        if not 0 <= passport.original_risk <= 100 or not 0 <= passport.residual_risk <= 100:
            raise MCPClientError("change passport risk score is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", passport.evidence_hash):
            raise MCPClientError("change passport evidence hash is invalid")
        try:
            markdown_size = len(passport.markdown.encode("utf-8"))
        except UnicodeError as exc:
            raise MCPClientError("change passport document is not valid UTF-8") from exc
        if not passport.markdown or markdown_size > 8192:
            raise MCPClientError("change passport document is empty or too large")
        if (
            passport.document_urn is not None
            and _DOCUMENT_URN.fullmatch(passport.document_urn) is None
        ):
            raise MCPClientError("change passport document URN is invalid")

    def _index_file(self, passport: ChangePassport) -> Path | None:
        root = self.document_index_path
        if root is None:
            return None
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", passport.run_id):
            raise MCPClientError("run ID is unsafe for the document index")
        try:
            if root.is_symlink():
                raise MCPClientError("document index must not be a symbolic link")
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not root.is_dir():
                raise MCPClientError("document index is not a directory")
            root.chmod(0o700)
        except MCPClientError:
            raise
        except OSError as exc:
            raise MCPClientError("document index is unavailable") from exc
        return root / f"{passport.run_id}.json"

    def _acquire_write_lock(self, passport: ChangePassport) -> int | None:
        path = self._index_file(passport)
        if path is None:
            return None
        lock_path = path.with_suffix(".lock")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise MCPClientError("document index lock is unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise MCPClientError("document index lock is not an owner-controlled file")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(descriptor)
            raise MCPClientError("writeback for this run is already in progress") from exc
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _release_write_lock(descriptor: int | None) -> None:
        if descriptor is None:
            return
        with suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        with suppress(OSError):
            os.close(descriptor)

    def _load_document_journal(self, passport: ChangePassport) -> _DocumentJournalEntry | None:
        path = self._index_file(passport)
        if path is None:
            return None
        if path.is_symlink():
            raise MCPClientError("document index is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > 8192
            ):
                raise MCPClientError("document index is not an owner-only regular file")
            with os.fdopen(descriptor, encoding="utf-8") as stream:
                descriptor = -1
                payload = json.load(stream)
        except MCPClientError:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            raise MCPClientError("document index is invalid") from exc
        if not isinstance(payload, dict):
            raise MCPClientError("document index entry is invalid")
        evidence_hash = payload.get("evidence_hash")
        document_urn = payload.get("document_urn")
        schema_version = payload.get("schema_version")
        if payload.get("run_id") != passport.run_id or evidence_hash != passport.evidence_hash:
            raise MCPClientError("document index entry does not match this run")
        if schema_version == "1.0":
            if (
                set(payload) != {"schema_version", "run_id", "evidence_hash", "document_urn"}
                or not isinstance(document_urn, str)
                or _DOCUMENT_URN.fullmatch(document_urn) is None
            ):
                raise MCPClientError("document index entry is invalid")
            return _DocumentJournalEntry(save_state="BOUND", document_urn=document_urn)
        if (
            schema_version != "1.1"
            or set(payload)
            != {"schema_version", "run_id", "evidence_hash", "save_state", "document_urn"}
            or payload.get("save_state") not in {"ATTEMPTED", "BOUND"}
        ):
            raise MCPClientError("document index entry is invalid")
        save_state = payload["save_state"]
        if save_state == "ATTEMPTED" and document_urn is not None:
            raise MCPClientError("document save-attempt journal is invalid")
        if save_state == "BOUND" and (
            not isinstance(document_urn, str) or _DOCUMENT_URN.fullmatch(document_urn) is None
        ):
            raise MCPClientError("document index contains an invalid document URN")
        return _DocumentJournalEntry(save_state=save_state, document_urn=document_urn)

    def _write_document_journal(
        self, passport: ChangePassport, *, save_state: str, document_urn: str | None
    ) -> bool:
        path = self._index_file(passport)
        if path is None:
            return False
        if path.is_symlink() or (path.exists() and not stat.S_ISREG(path.stat().st_mode)):
            raise MCPClientError("document index is not a regular file")
        payload = {
            "schema_version": "1.1",
            "run_id": passport.run_id,
            "evidence_hash": passport.evidence_hash,
            "save_state": save_state,
            "document_urn": document_urn,
        }
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                json.dump(payload, stream, indent=2, sort_keys=True, ensure_ascii=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException as exc:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            temporary.unlink(missing_ok=True)
            raise MCPClientError("document index could not be updated") from exc
        return True

    def _remember_save_attempt(self, passport: ChangePassport) -> bool:
        return self._write_document_journal(
            passport,
            save_state="ATTEMPTED",
            document_urn=None,
        )

    def _remember_document(self, passport: ChangePassport, document_urn: str) -> None:
        self._write_document_journal(
            passport,
            save_state="BOUND",
            document_urn=document_urn,
        )

    async def _read_identity_once(
        self,
        passport: ChangePassport,
        document_urn: str,
        readback_digests: list[str],
    ) -> Mapping[str, Any]:
        source_response = await self.mcp.call_read("get_entities", {"urns": [passport.source_urn]})
        readback_digests.append(source_response.digest)
        source = _entities_by_urn(source_response.data).get(passport.source_urn)
        if source is None or not _related_document_matches(source, passport, document_urn):
            raise _ReadbackMismatch("document relation failed identity readback")

        exact_pattern = rf"(?s)\A{re.escape(passport.markdown)}\z"
        document_response = await self.mcp.call_read(
            "grep_documents",
            {
                "urns": [document_urn],
                "pattern": exact_pattern,
                "context_chars": 0,
                "max_matches_per_doc": 1,
                "start_offset": 0,
            },
        )
        readback_digests.append(document_response.digest)
        if not _grep_document_matches(document_response.data, passport, document_urn):
            raise _ReadbackMismatch("document content failed identity readback")
        return source

    async def _read_identity(
        self,
        passport: ChangePassport,
        document_urn: str,
        readback_digests: list[str],
    ) -> Mapping[str, Any]:
        """Retry bounded readback while search-backed projections converge."""

        for attempt in range(1, self.readback_attempts + 1):
            try:
                return await self._read_identity_once(passport, document_urn, readback_digests)
            except _ReadbackMismatch:
                if attempt == self.readback_attempts:
                    raise
                await asyncio.sleep(self.readback_retry_delay_seconds * (2 ** (attempt - 1)))
        raise AssertionError("readback attempt loop exhausted")  # pragma: no cover

    async def _recover_document_urn(
        self, passport: ChangePassport, readback_digests: list[str]
    ) -> tuple[str | None, bool]:
        title = f"LineageGuard change passport {passport.run_id}"
        offset = 0
        expected_total: int | None = None
        exact: dict[str, str] = {}
        seen: set[str] = set()
        try:
            for _page in range(10):
                response = await self.mcp.call_read(
                    "search_documents",
                    {
                        "query": f'/q "{title}"',
                        "num_results": 50,
                        "offset": offset,
                    },
                )
                readback_digests.append(response.digest)
                data = response.data
                if not isinstance(data, Mapping):
                    raise _ReadbackMismatch("document recovery search is not an object")
                total = data.get("total")
                start = data.get("start")
                results = data.get("searchResults")
                if results is None and total == 0:
                    # Pinned MCP 0.6.0 omits searchResults for an empty page.
                    results = []
                if (
                    not isinstance(total, int)
                    or isinstance(total, bool)
                    or total < 0
                    or start != offset
                    or not isinstance(results, list)
                    or offset + len(results) > total
                ):
                    raise _ReadbackMismatch("document recovery pagination is invalid")
                if expected_total is None:
                    expected_total = total
                elif total != expected_total:
                    raise _ReadbackMismatch("document recovery total changed")
                for result in results:
                    entity = result.get("entity") if isinstance(result, Mapping) else None
                    urn = entity.get("urn") if isinstance(entity, Mapping) else None
                    info = entity.get("info") if isinstance(entity, Mapping) else None
                    observed_title = info.get("title") if isinstance(info, Mapping) else None
                    if (
                        not isinstance(urn, str)
                        or _DOCUMENT_URN.fullmatch(urn) is None
                        or not isinstance(observed_title, str)
                        or urn in seen
                    ):
                        raise _ReadbackMismatch("document recovery identities are invalid")
                    seen.add(urn)
                    if observed_title == title:
                        exact[urn] = observed_title
                if offset + len(results) == total:
                    break
                if not results:
                    raise _ReadbackMismatch("document recovery pagination stalled")
                offset += len(results)
            else:
                raise _ReadbackMismatch("document recovery search was truncated")
        except MCPMissingCapability:
            return None, False

        if len(exact) > 1:
            raise _ReadbackMismatch("document recovery identity is ambiguous")
        if not exact:
            return None, True
        document_urn = next(iter(exact))
        await self._read_identity(passport, document_urn, readback_digests)
        return document_urn, True

    async def persist(self, passport: ChangePassport) -> WritebackResult:
        mutation_digests: list[str] = []
        readback_digests: list[str] = []
        document_urn = passport.document_urn
        save_attempted = False
        recovered_after_attempt = False
        lock_descriptor: int | None = None
        try:
            self._validate_passport(passport)
            lock_descriptor = self._acquire_write_lock(passport)
            if document_urn is None:
                journal = self._load_document_journal(passport)
                if journal is not None:
                    document_urn = journal.document_urn
                    save_attempted = journal.save_state == "ATTEMPTED"
            if document_urn is None:
                document_urn, _recovery_available = await self._recover_document_urn(
                    passport, readback_digests
                )
                recovered_after_attempt = save_attempted and document_urn is not None
                if document_urn is not None:
                    self._remember_document(passport, document_urn)
                elif save_attempted:
                    raise _ReadbackMismatch("a previous document save has an ambiguous outcome")
                elif self.document_index_path is None:
                    raise MCPMissingCapability(
                        "save_document creation requires a durable document journal"
                    )
            if document_urn is not None:
                existing_source = await self._read_identity(
                    passport, document_urn, readback_digests
                )
                if _source_matches(
                    existing_source,
                    passport,
                    writeback_state="VERIFIED",
                    tag=True,
                ):
                    self._remember_document(passport, document_urn)
                    return WritebackResult(
                        status=WritebackStatus.VERIFIED,
                        document_urn=document_urn,
                        mutation_digests=(),
                        readback_digests=tuple(readback_digests),
                    )

            properties = await self.mcp.call_mutation(
                "add_structured_properties",
                {
                    "property_values": {
                        f"{PROPERTY_PREFIX}runId": [passport.run_id],
                        f"{PROPERTY_PREFIX}originalRisk": [passport.original_risk],
                        f"{PROPERTY_PREFIX}residualRisk": [passport.residual_risk],
                        f"{PROPERTY_PREFIX}decision": [passport.decision],
                        f"{PROPERTY_PREFIX}remediationStatus": [passport.remediation_status],
                        f"{PROPERTY_PREFIX}evidenceHash": [passport.evidence_hash],
                        f"{PROPERTY_PREFIX}commitSha": [passport.commit_sha],
                        f"{PROPERTY_PREFIX}writebackState": ["PENDING"],
                    },
                    "entity_urns": [passport.source_urn],
                },
            )
            mutation_digests.append(properties.digest)

            if not recovered_after_attempt:
                requested_document_urn = document_urn
                if requested_document_urn is None:
                    journaled = self._remember_save_attempt(passport)
                    if not journaled:
                        raise MCPMissingCapability(
                            "save_document creation requires a durable document journal"
                        )
                document = await self.mcp.call_mutation(
                    "save_document",
                    {
                        "document_type": "Decision",
                        "title": f"LineageGuard change passport {passport.run_id}",
                        "content": passport.markdown,
                        **({"urn": document_urn} if document_urn is not None else {}),
                        "topics": ["lineageguard", "schema-change", passport.decision.casefold()],
                        "related_assets": [passport.source_urn],
                    },
                )
                mutation_digests.append(document.digest)
                saved_document_urn = _extract_document_urn(document)
                if saved_document_urn is None:
                    raise MCPClientError("save_document returned no document URN")
                if (
                    requested_document_urn is not None
                    and saved_document_urn != requested_document_urn
                ):
                    raise _ReadbackMismatch("save_document changed the verified document identity")
                document_urn = saved_document_urn
                self._remember_document(passport, document_urn)

            if document_urn is None:  # pragma: no cover - guarded by save/recovery above
                raise MCPClientError("document identity is unavailable after save")
            pending_source = await self._read_identity(passport, document_urn, readback_digests)
            if not _source_matches(pending_source, passport, writeback_state="PENDING", tag=None):
                raise _ReadbackMismatch("pending writeback failed identity readback")

            removed_tags = await self.mcp.call_mutation(
                "remove_tags",
                {
                    "tag_urns": sorted(DECISION_TAGS),
                    "entity_urns": [passport.source_urn],
                },
            )
            mutation_digests.append(removed_tags.digest)
            tag_urn = f"urn:li:tag:LineageGuard_{passport.decision}"
            tags = await self.mcp.call_mutation(
                "add_tags", {"tag_urns": [tag_urn], "entity_urns": [passport.source_urn]}
            )
            mutation_digests.append(tags.digest)
            tag_readback = await self.mcp.call_read("get_entities", {"urns": [passport.source_urn]})
            readback_digests.append(tag_readback.digest)
            tag_source = _entities_by_urn(tag_readback.data).get(passport.source_urn)
            if tag_source is None or not _source_matches(
                tag_source, passport, writeback_state="PENDING", tag=True
            ):
                raise _ReadbackMismatch("decision tag failed pending-state readback")

            verified_state = await self.mcp.call_mutation(
                "add_structured_properties",
                {
                    "property_values": {
                        f"{PROPERTY_PREFIX}writebackState": ["VERIFIED"],
                    },
                    "entity_urns": [passport.source_urn],
                },
            )
            mutation_digests.append(verified_state.digest)
            final_source = await self._read_identity(passport, document_urn, readback_digests)
            if not _source_matches(final_source, passport, writeback_state="VERIFIED", tag=True):
                raise _ReadbackMismatch("final writeback failed identity readback")
        except MCPClientError as exc:
            return WritebackResult(
                status=WritebackStatus.WRITEBACK_PENDING,
                document_urn=document_urn,
                mutation_digests=tuple(mutation_digests),
                readback_digests=tuple(readback_digests),
                reason=(
                    "readback_mismatch"
                    if isinstance(exc, _ReadbackMismatch)
                    else type(exc).__name__
                ),
            )
        finally:
            self._release_write_lock(lock_descriptor)

        return WritebackResult(
            status=WritebackStatus.VERIFIED,
            document_urn=document_urn,
            mutation_digests=tuple(mutation_digests),
            readback_digests=tuple(readback_digests),
        )
