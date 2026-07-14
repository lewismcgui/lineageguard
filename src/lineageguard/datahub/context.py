"""Translate DataHub MCP and assertion evidence into deterministic risk inputs."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, TypeGuard
from urllib.parse import unquote

from lineageguard.datahub.graphql import AssertionPage, DataHubGraphQLClient, GraphQLError
from lineageguard.datahub.mcp_client import MCPClientError, MCPToolResponse
from lineageguard.models import (
    AssetType,
    EvidenceKind,
    EvidenceRecord,
    EvidenceState,
    EvidenceStatus,
    ImpactedAsset,
    SchemaChange,
    SchemaChangeType,
)

_ENTITY_URN = re.compile(r"^urn:li:[A-Za-z][A-Za-z0-9]*:\S+$")
_ADDITIVE_CHANGE_TYPES = frozenset(
    {
        SchemaChangeType.ADD_COLUMN,
        SchemaChangeType.ADD_REQUIRED_COLUMN,
        SchemaChangeType.ADD_NULLABLE_COLUMN,
    }
)


class MCPReader(Protocol):
    async def call_read(
        self, tool: str, arguments: Mapping[str, Any] | None = None
    ) -> MCPToolResponse: ...


@dataclass(frozen=True, slots=True)
class ContextCollection:
    """Catalog context and its explicit evidence coverage."""

    source_urn: str | None
    impacted_assets: tuple[ImpactedAsset, ...]
    evidence_state: EvidenceState
    response_digests: tuple[str, ...]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _SchemaFieldPage:
    fields: tuple[Mapping[str, Any], ...]
    total: int
    remaining: int
    matching: int | None


def _walk(value: object) -> Iterable[object]:
    yield value
    if isinstance(value, Mapping):
        for nested in value.values():
            yield from _walk(nested)
    elif isinstance(value, list | tuple):
        for nested in value:
            yield from _walk(nested)


def _urns(value: object, *, prefix: str | None = None) -> tuple[str, ...]:
    found = {
        item
        for item in _walk(value)
        if isinstance(item, str)
        and item.startswith(prefix or "urn:li:")
        and not item.startswith("urn:li:dataPlatform:")
    }
    return tuple(sorted(found))


def _asset_type(urn: str) -> AssetType:
    prefix_map = {
        "urn:li:dataset:": AssetType.DATASET,
        "urn:li:dashboard:": AssetType.DASHBOARD,
        "urn:li:chart:": AssetType.CHART,
        "urn:li:dataJob:": AssetType.DATA_JOB,
        "urn:li:dataFlow:": AssetType.DATA_FLOW,
        "urn:li:assertion:": AssetType.ASSERTION,
    }
    for prefix, kind in prefix_map.items():
        if urn.startswith(prefix):
            return kind
    return AssetType.OTHER


def _valid_entity_urn(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _ENTITY_URN.fullmatch(value) is not None


def _find_first_string(value: object, keys: Sequence[str]) -> str | None:
    if isinstance(value, Mapping):
        for key in keys:
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        for nested in value.values():
            match = _find_first_string(nested, keys)
            if match is not None:
                return match
    elif isinstance(value, list | tuple):
        for nested in value:
            match = _find_first_string(nested, keys)
            if match is not None:
                return match
    return None


def _contains_key(value: object, key: str) -> bool:
    return any(isinstance(item, Mapping) and key in item for item in _walk(value))


def _owners(entity: Mapping[str, Any]) -> tuple[str, ...] | None:
    if "ownership" not in entity:
        return None
    ownership = entity.get("ownership")
    entries = ownership.get("owners") if isinstance(ownership, Mapping) else None
    if not isinstance(entries, list):
        raise MCPClientError("DataHub ownership evidence is malformed")
    owner_urns: set[str] = set()
    for entry in entries:
        owner = entry.get("owner") if isinstance(entry, Mapping) else None
        urn = owner.get("urn") if isinstance(owner, Mapping) else None
        if (
            not isinstance(urn, str)
            or not urn.startswith(("urn:li:corpuser:", "urn:li:corpGroup:"))
            or urn in owner_urns
        ):
            raise MCPClientError("DataHub ownership evidence is malformed")
        owner_urns.add(urn)
    return tuple(sorted(owner_urns))


def _tag_text(entity: Mapping[str, Any]) -> str:
    present = [key for key in ("globalTags", "tags") if key in entity]
    if not present:
        return ""
    if len(present) != 1:
        raise MCPClientError("DataHub tag evidence is ambiguous")
    container = entity.get(present[0])
    entries = container.get("tags") if isinstance(container, Mapping) else None
    if not isinstance(entries, list):
        raise MCPClientError("DataHub tag evidence is malformed")
    values: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        tag = entry.get("tag") if isinstance(entry, Mapping) else None
        if not isinstance(tag, Mapping):
            raise MCPClientError("DataHub tag evidence is malformed")
        urn = tag.get("urn")
        if not isinstance(urn, str) or not urn.startswith("urn:li:tag:") or urn in seen:
            raise MCPClientError("DataHub tag evidence is malformed")
        seen.add(urn)
        values.append(urn.casefold())
        properties = tag.get("properties")
        if properties is not None:
            if not isinstance(properties, Mapping):
                raise MCPClientError("DataHub tag evidence is malformed")
            name = properties.get("name")
            if name is not None and not isinstance(name, str):
                raise MCPClientError("DataHub tag evidence is malformed")
            if isinstance(name, str):
                values.append(name.casefold())
    return " ".join(values)


def _entity_page(data: object, requested_urns: Sequence[str]) -> dict[str, Mapping[str, Any]]:
    """Bind one get_entities response to its exact top-level request."""

    expected = set(requested_urns)
    if len(expected) != len(requested_urns) or not isinstance(data, list):
        raise MCPClientError("DataHub entity enrichment response is malformed")
    entities: dict[str, Mapping[str, Any]] = {}
    for entity in data:
        if not isinstance(entity, Mapping):
            raise MCPClientError("DataHub entity enrichment response is malformed")
        urn = entity.get("urn")
        if (
            not _valid_entity_urn(urn)
            or urn not in expected
            or urn in entities
            or "error" in entity
        ):
            raise MCPClientError("DataHub entity enrichment identities are invalid")
        # Validate every risk-bearing shape before accepting the page. This is
        # intentionally separate from display-name discovery, which is not a
        # decision input.
        _owners(entity)
        _tag_text(entity)
        entities[urn] = entity
    if set(entities) != expected:
        raise MCPClientError("DataHub entity enrichment response is incomplete")
    return entities


def _schema_field_page(data: object, expected_urn: str) -> _SchemaFieldPage:
    if not isinstance(data, Mapping) or data.get("urn") != expected_urn:
        raise MCPClientError("DataHub schema response is not bound to the requested dataset")
    raw_fields = data.get("fields")
    if not isinstance(raw_fields, list) or any(
        not isinstance(field, Mapping) for field in raw_fields
    ):
        raise MCPClientError("DataHub schema fields are malformed")
    total = _strict_int(data.get("totalFields"))
    returned = _strict_int(data.get("returned"))
    remaining = _strict_int(data.get("remainingCount"))
    raw_matching = data.get("matchingCount")
    matching = _strict_int(raw_matching)
    offset = _strict_int(data.get("offset"))
    if (
        total is None
        or returned is None
        or remaining is None
        or offset != 0
        or returned != len(raw_fields)
        or not 0 <= returned <= 100
        or remaining < 0
        or total != returned + remaining
        or (matching is None and not (raw_matching is None and total == 0))
        or (matching is not None and not 0 <= matching <= total)
    ):
        raise MCPClientError("DataHub schema pagination is invalid")
    return _SchemaFieldPage(
        fields=tuple(raw_fields),
        total=total,
        remaining=remaining,
        matching=matching,
    )


def _field_path(field: Mapping[str, Any]) -> str | None:
    for key in ("fieldPath", "path", "name"):
        value = field.get(key)
        if isinstance(value, str):
            return value
    return None


def _field_native_type(field: Mapping[str, Any]) -> str | None:
    for key in ("nativeDataType", "nativeType"):
        value = field.get(key)
        if isinstance(value, str):
            return value
    return None


def _type_fingerprint(value: str) -> str:
    """Ignore catalog formatting whitespace while retaining semantic spelling."""

    return "".join(value.casefold().split())


def _dataset_qualified_name(urn: str) -> str | None:
    prefix = "urn:li:dataset:("
    if not urn.startswith(prefix) or not urn.endswith(")"):
        return None
    inner = urn[len(prefix) : -1]
    first_comma = inner.find(",")
    last_comma = inner.rfind(",")
    if first_comma < 0 or last_comma <= first_comma:
        return None
    name = unquote(inner[first_comma + 1 : last_comma]).strip()
    return name or None


def _lineage_results(data: object) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(data, Mapping):
        return ()
    downstreams = data.get("downstreams")
    if not isinstance(downstreams, Mapping):
        return ()
    results = downstreams.get("searchResults")
    if not isinstance(results, list):
        return ()
    return tuple(item for item in results if isinstance(item, Mapping))


def _strict_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _lineage_entity(item: Mapping[str, Any]) -> Mapping[str, Any] | None:
    entity = item.get("entity")
    return entity if isinstance(entity, Mapping) else None


def _assertion_field_paths(assertion: Mapping[str, Any]) -> frozenset[str]:
    info = assertion.get("info")
    dataset_assertion = info.get("datasetAssertion") if isinstance(info, Mapping) else None
    fields = dataset_assertion.get("fields") if isinstance(dataset_assertion, Mapping) else None
    if not isinstance(fields, list):
        return frozenset()
    paths: set[str] = set()
    for field in fields:
        if not isinstance(field, Mapping):
            continue
        path = field.get("path")
        if isinstance(path, str) and path:
            paths.add(path.casefold())
    return frozenset(paths)


class DataHubContextCollector:
    """Collect the exact DataHub signals needed by the risk engine."""

    def __init__(
        self,
        mcp: MCPReader,
        graphql: DataHubGraphQLClient,
        *,
        max_hops: int = 3,
        page_size: int = 100,
        max_pages: int = 10,
    ) -> None:
        self.mcp = mcp
        self.graphql = graphql
        self.max_hops = max_hops
        if not 1 <= page_size <= 100:
            raise ValueError("lineage page_size must be between 1 and 100")
        if max_pages < 1:
            raise ValueError("lineage max_pages must be positive")
        self.page_size = page_size
        self.max_pages = max_pages

    async def collect(self, change: SchemaChange) -> ContextCollection:
        records: list[EvidenceRecord] = []
        digests: list[str] = []
        reasons: list[str] = []

        source_urn, catalog_status = await self._resolve(change, records, digests, reasons)
        if source_urn is None:
            return ContextCollection(
                source_urn=None,
                impacted_assets=(),
                evidence_state=EvidenceState(
                    catalog=catalog_status,
                    lineage=EvidenceStatus.MISSING,
                    traversal=EvidenceStatus.MISSING,
                    ownership=EvidenceStatus.MISSING,
                    assertions=EvidenceStatus.MISSING,
                    records=tuple(records),
                ),
                response_digests=tuple(sorted(digests)),
                reason_codes=tuple(sorted(set(reasons))),
            )

        lineage_items, lineage_status, traversal_status = await self._lineage(
            source_urn, change, records, digests, reasons
        )
        impacted, ownership_status = await self._enrich(lineage_items, records, digests, reasons)
        impacted, assertion_assets, assertion_status = await self._assertions(
            source_urn, change, lineage_items, impacted, records, digests, reasons
        )
        combined = {asset.urn: asset for asset in (*impacted, *assertion_assets)}

        return ContextCollection(
            source_urn=source_urn,
            impacted_assets=tuple(combined[urn] for urn in sorted(combined)),
            evidence_state=EvidenceState(
                catalog=catalog_status,
                lineage=lineage_status,
                traversal=traversal_status,
                ownership=ownership_status,
                assertions=assertion_status,
                records=tuple(records),
            ),
            response_digests=tuple(sorted(digests)),
            reason_codes=tuple(sorted(set(reasons))),
        )

    async def _resolve(
        self,
        change: SchemaChange,
        records: list[EvidenceRecord],
        digests: list[str],
        reasons: list[str],
    ) -> tuple[str | None, EvidenceStatus]:
        candidates: tuple[str, ...]
        direct_urn = change.relation.startswith("urn:li:dataset:")
        if direct_urn:
            candidates = (change.relation,)
            search_digest = "direct-urn"
        else:
            search_digests: list[str] = []
            collected_candidates: set[str] = set()
            offset = 0
            expected_total: int | None = None
            try:
                for _page in range(self.max_pages):
                    response = await self.mcp.call_read(
                        "search",
                        {
                            "query": f"/q {change.relation}",
                            "filter": "entity_type = dataset",
                            "num_results": 50,
                            "offset": offset,
                        },
                    )
                    digests.append(response.digest)
                    search_digests.append(response.digest)
                    data = response.data
                    if not isinstance(data, Mapping):
                        raise MCPClientError("DataHub search response is not an object")
                    total = _strict_int(data.get("total"))
                    returned_start = _strict_int(data.get("start"))
                    results = data.get("searchResults")
                    if (
                        total is None
                        or total < 0
                        or returned_start != offset
                        or not isinstance(results, list)
                        or offset + len(results) > total
                    ):
                        raise MCPClientError("DataHub search pagination is invalid")
                    if expected_total is None:
                        expected_total = total
                    elif total != expected_total:
                        raise MCPClientError("DataHub search total changed during pagination")
                    page_candidates: set[str] = set()
                    for result in results:
                        entity = result.get("entity") if isinstance(result, Mapping) else None
                        urn = entity.get("urn") if isinstance(entity, Mapping) else None
                        if (
                            not isinstance(urn, str)
                            or not urn.startswith("urn:li:dataset:")
                            or _dataset_qualified_name(urn) is None
                            or urn in page_candidates
                        ):
                            raise MCPClientError(
                                "DataHub search returned malformed dataset identities"
                            )
                        page_candidates.add(urn)
                    if collected_candidates.intersection(page_candidates):
                        raise MCPClientError("DataHub search returned malformed dataset identities")
                    collected_candidates.update(page_candidates)
                    if offset + len(results) == total:
                        break
                    if not results:
                        raise MCPClientError("DataHub search pagination stalled")
                    offset += len(results)
                else:
                    reasons.append("catalog.search_truncated")
                    return None, EvidenceStatus.TRUNCATED
            except MCPClientError:
                reasons.append("catalog.search_unavailable")
                return None, EvidenceStatus.UNAVAILABLE
            search_digest = search_digests[-1] if search_digests else "missing"
            candidates = tuple(sorted(collected_candidates))

        if direct_urn:
            exact = candidates if _dataset_qualified_name(change.relation) is not None else ()
        else:
            normalized = change.relation.casefold().replace('"', "")
            exact = tuple(
                urn
                for urn in candidates
                if (_dataset_qualified_name(urn) or "").casefold() == normalized
            )
        if len(exact) != 1:
            status = EvidenceStatus.AMBIGUOUS if candidates else EvidenceStatus.MISSING
            reasons.append(f"catalog.dataset_{status.value}")
            records.append(
                EvidenceRecord(
                    id=f"mcp-search:{search_digest}",
                    kind=EvidenceKind.CATALOG,
                    status=status,
                    source="DataHub MCP search",
                    detail=f"candidate_count={len(candidates)} exact_count={len(exact)}",
                    critical=True,
                )
            )
            return None, status

        source_urn = exact[0]
        column = (
            change.new_column
            if change.change_type in _ADDITIVE_CHANGE_TYPES
            else change.old_column or change.new_column
        )
        if column is None:
            reasons.append("catalog.change_column_missing")
            return None, EvidenceStatus.MISSING
        try:
            schema_response = await self.mcp.call_read(
                "list_schema_fields",
                {"urn": source_urn, "keywords": [column], "limit": 100, "offset": 0},
            )
        except MCPClientError:
            reasons.append("catalog.schema_unavailable")
            return None, EvidenceStatus.UNAVAILABLE
        digests.append(schema_response.digest)
        try:
            schema_page = _schema_field_page(schema_response.data, source_urn)
        except MCPClientError:
            reasons.append("catalog.schema_unavailable")
            return None, EvidenceStatus.UNAVAILABLE
        matches = tuple(
            field
            for field in schema_page.fields
            if (_field_path(field) or "").casefold() == column.casefold()
        )
        status = EvidenceStatus.COMPLETE
        if change.change_type in _ADDITIVE_CHANGE_TYPES:
            if matches:
                status = EvidenceStatus.STALE
                reasons.append("catalog.addition_column_exists")
            elif schema_page.remaining == 0 or schema_page.matching == 0:
                # An exhausted schema result, or an authoritative zero keyword
                # match across the complete schema, proves exact absence.
                status = EvidenceStatus.COMPLETE
            else:
                status = EvidenceStatus.TRUNCATED
                reasons.append("catalog.schema_truncated")
        elif len(matches) != 1:
            status = EvidenceStatus.STALE if schema_page.fields else EvidenceStatus.MISSING
            reasons.append(f"catalog.column_{status.value}")
        elif change.old_type is not None:
            observed_type = _field_native_type(matches[0])
            if observed_type is None:
                status = EvidenceStatus.MISSING
                reasons.append("catalog.type_fingerprint_missing")
            elif _type_fingerprint(observed_type) != _type_fingerprint(change.old_type):
                status = EvidenceStatus.STALE
                reasons.append("catalog.type_fingerprint_stale")
        records.append(
            EvidenceRecord(
                id=f"mcp-schema:{schema_response.digest}",
                kind=EvidenceKind.CATALOG,
                status=status,
                source="DataHub MCP list_schema_fields",
                detail=f"dataset={source_urn} column={column}",
                critical=True,
            )
        )
        return source_urn, status

    async def _lineage(
        self,
        source_urn: str,
        change: SchemaChange,
        records: list[EvidenceRecord],
        digests: list[str],
        reasons: list[str],
    ) -> tuple[tuple[Mapping[str, Any], ...], EvidenceStatus, EvidenceStatus]:
        column = change.old_column or change.new_column
        collected: dict[str, Mapping[str, Any]] = {}
        offset = 0
        traversal_status = EvidenceStatus.COMPLETE
        expected_total: int | None = None

        try:
            for _page in range(self.max_pages):
                response = await self.mcp.call_read(
                    "get_lineage",
                    {
                        "urn": source_urn,
                        "column": column,
                        "upstream": False,
                        "max_hops": self.max_hops,
                        "max_results": self.page_size,
                        "offset": offset,
                    },
                )
                digests.append(response.digest)
                data = response.data
                downstreams = data.get("downstreams") if isinstance(data, Mapping) else None
                page = _lineage_results(response.data)
                if not isinstance(downstreams, Mapping):
                    traversal_status = EvidenceStatus.TRUNCATED
                    break

                total = _strict_int(downstreams.get("total"))
                if total is None or total < 0:
                    traversal_status = EvidenceStatus.TRUNCATED
                    break
                if expected_total is None:
                    expected_total = total
                elif total != expected_total:
                    traversal_status = EvidenceStatus.TRUNCATED
                    break

                response_offset = _strict_int(downstreams.get("offset"))
                returned = _strict_int(downstreams.get("returned"))
                has_more = downstreams.get("hasMore")
                if (
                    response_offset != offset
                    or returned != len(page)
                    or not isinstance(has_more, bool)
                    or offset + len(page) > total
                ):
                    traversal_status = EvidenceStatus.TRUNCATED
                    break

                # mcp-server-datahub 0.6.0 always fetches GraphQL start=0 and
                # at most max_results before applying offset locally. Totals
                # above this window cannot be exhaustively paged.
                window_exceeded = total > self.page_size
                if total == 0:
                    if page or response_offset != 0 or returned != 0 or has_more is not False:
                        traversal_status = EvidenceStatus.TRUNCATED
                    break

                malformed_page = False
                for item in page:
                    entity = _lineage_entity(item)
                    urn = entity.get("urn") if entity is not None else None
                    degree = _strict_int(item.get("degree"))
                    if (
                        not _valid_entity_urn(urn)
                        or urn in collected
                        or degree is None
                        or not 1 <= degree <= self.max_hops
                    ):
                        malformed_page = True
                        break
                    collected[urn] = item
                    truncated_children = item.get("truncatedChildren")
                    if (
                        truncated_children is not None and not isinstance(truncated_children, bool)
                    ) or truncated_children is True:
                        malformed_page = True
                        break
                if malformed_page:
                    traversal_status = EvidenceStatus.TRUNCATED
                    break
                if window_exceeded:
                    traversal_status = EvidenceStatus.TRUNCATED
                    break

                expected_has_more = offset + len(page) < total
                if has_more != expected_has_more:
                    traversal_status = EvidenceStatus.TRUNCATED
                    break
                if not has_more:
                    if len(collected) != total:
                        traversal_status = EvidenceStatus.TRUNCATED
                    break
                if returned == 0:
                    traversal_status = EvidenceStatus.TRUNCATED
                    break
                offset += returned
            else:
                traversal_status = EvidenceStatus.TRUNCATED
        except MCPClientError:
            reasons.append("lineage.unavailable")
            return (), EvidenceStatus.UNAVAILABLE, EvidenceStatus.UNAVAILABLE

        if traversal_status is not EvidenceStatus.COMPLETE:
            reasons.append("lineage.truncated")
        digest_ref = digests[-1] if digests else "missing"
        records.append(
            EvidenceRecord(
                id=f"mcp-lineage:{digest_ref}",
                kind=EvidenceKind.LINEAGE,
                status=EvidenceStatus.COMPLETE,
                source="DataHub MCP get_lineage",
                detail=f"source={source_urn} column={column} assets={len(collected)}",
                critical=True,
            )
        )
        records.append(
            EvidenceRecord(
                id=f"mcp-traversal:{digest_ref}",
                kind=EvidenceKind.TRAVERSAL,
                status=traversal_status,
                source="DataHub MCP get_lineage pagination",
                critical=True,
            )
        )
        return (
            tuple(collected[urn] for urn in sorted(collected)),
            EvidenceStatus.COMPLETE,
            traversal_status,
        )

    async def _enrich(
        self,
        lineage_items: tuple[Mapping[str, Any], ...],
        records: list[EvidenceRecord],
        digests: list[str],
        reasons: list[str],
    ) -> tuple[tuple[ImpactedAsset, ...], EvidenceStatus]:
        urn_to_item: dict[str, Mapping[str, Any]] = {}
        for item in lineage_items:
            entity = _lineage_entity(item)
            urn = entity.get("urn") if entity is not None else None
            if isinstance(urn, str):
                urn_to_item[urn] = item
        if not urn_to_item:
            records.append(
                EvidenceRecord(
                    id="mcp-entities:none",
                    kind=EvidenceKind.OWNERSHIP,
                    status=EvidenceStatus.COMPLETE,
                    source="DataHub MCP get_lineage",
                    detail="No downstream entities to enrich.",
                    critical=True,
                )
            )
            return (), EvidenceStatus.COMPLETE

        enriched: dict[str, Mapping[str, Any]] = {}
        try:
            urns = sorted(urn_to_item)
            for start in range(0, len(urns), 10):
                requested = urns[start : start + 10]
                response = await self.mcp.call_read("get_entities", {"urns": requested})
                digests.append(response.digest)
                enriched.update(_entity_page(response.data, requested))
        except MCPClientError:
            reasons.append("ownership.enrichment_unavailable")
            return (), EvidenceStatus.UNAVAILABLE

        if set(enriched) != set(urn_to_item):
            reasons.append("ownership.enrichment_incomplete")
            ownership_status = EvidenceStatus.MISSING
        else:
            ownership_status = EvidenceStatus.COMPLETE
        digest_ref = digests[-1] if digests else "missing"
        records.append(
            EvidenceRecord(
                id=f"mcp-entities:{digest_ref}",
                kind=EvidenceKind.OWNERSHIP,
                status=ownership_status,
                source="DataHub MCP get_entities",
                detail=f"enriched={len(enriched)} expected={len(urn_to_item)}",
                critical=True,
            )
        )

        assets: list[ImpactedAsset] = []
        lineage_ref = next(
            (record.id for record in reversed(records) if record.kind is EvidenceKind.LINEAGE),
            "mcp-lineage:missing",
        )
        for urn in sorted(urn_to_item):
            item = urn_to_item[urn]
            entity = enriched.get(urn, _lineage_entity(item) or {})
            tags = _tag_text(entity)
            degree = item.get("degree", 1)
            hop_count = degree if isinstance(degree, int) and degree >= 1 else 1
            direct = bool(item.get("lineageColumns"))
            assets.append(
                ImpactedAsset(
                    urn=urn,
                    asset_type=_asset_type(urn),
                    name=_find_first_string(entity, ("displayName", "name", "title")),
                    hop_count=hop_count,
                    owners=_owners(entity),
                    assertion_urns=(),
                    critical_asset=("critical" in tags or "finance" in tags),
                    sensitive_data=("pii" in tags or "sensitive" in tags),
                    direct_column_lineage=direct,
                    evidence_refs=(lineage_ref, f"mcp-entities:{digest_ref}"),
                )
            )
        return tuple(assets), ownership_status

    async def _assertions(
        self,
        source_urn: str,
        change: SchemaChange,
        lineage_items: tuple[Mapping[str, Any], ...],
        impacted: tuple[ImpactedAsset, ...],
        records: list[EvidenceRecord],
        digests: list[str],
        reasons: list[str],
    ) -> tuple[tuple[ImpactedAsset, ...], tuple[ImpactedAsset, ...], EvidenceStatus]:
        dataset_urns = [source_urn]
        dataset_urns.extend(
            asset.urn for asset in impacted if asset.asset_type is AssetType.DATASET
        )
        pages: list[tuple[str, AssertionPage]] = []
        assertion_status = EvidenceStatus.COMPLETE
        try:
            for urn in sorted(set(dataset_urns)):
                start = 0
                expected_total: int | None = None
                seen_assertions: set[str] = set()
                for _page_number in range(self.max_pages):
                    page = await asyncio.to_thread(
                        self.graphql.get_dataset_assertions,
                        urn,
                        start=start,
                        count=self.page_size,
                    )
                    digests.append(page.digest)
                    if expected_total is None:
                        expected_total = page.total
                    elif page.total != expected_total:
                        assertion_status = EvidenceStatus.TRUNCATED
                        reasons.append("assertions.total_changed")
                        break
                    returned = len(page.assertions)
                    page_urns: set[str] = set()
                    malformed_identity = False
                    for assertion in page.assertions:
                        urn_value = assertion.get("urn")
                        if (
                            not isinstance(urn_value, str)
                            or not urn_value.startswith("urn:li:assertion:")
                            or urn_value in page_urns
                        ):
                            malformed_identity = True
                            break
                        page_urns.add(urn_value)
                    if (
                        page.start != start
                        or page.count != returned
                        or returned > self.page_size
                        or start + returned > page.total
                        or malformed_identity
                        or seen_assertions.intersection(page_urns)
                    ):
                        assertion_status = EvidenceStatus.TRUNCATED
                        reasons.append("assertions.pagination_invalid")
                        break
                    seen_assertions.update(page_urns)
                    pages.append((urn, page))
                    if start + returned == page.total:
                        break
                    if returned == 0:
                        assertion_status = EvidenceStatus.TRUNCATED
                        reasons.append("assertions.pagination_stalled")
                        break
                    start += returned
                else:
                    assertion_status = EvidenceStatus.TRUNCATED
                    reasons.append("assertions.truncated")
        except (GraphQLError, OSError):
            reasons.append("assertions.unavailable")
            return impacted, (), EvidenceStatus.UNAVAILABLE

        assertions_by_dataset: dict[str, set[str]] = {}
        assertion_names: dict[str, str | None] = {}
        assertion_refs: dict[str, str] = {}
        recorded_assertions: set[str] = set()
        relevant_columns: dict[str, set[str]] = {
            source_urn: {
                column.casefold()
                for column in (change.old_column, change.new_column)
                if isinstance(column, str)
            }
        }
        for item in lineage_items:
            entity = _lineage_entity(item)
            lineage_urn = entity.get("urn") if entity is not None else None
            columns = item.get("lineageColumns")
            if not isinstance(lineage_urn, str) or not isinstance(columns, list):
                continue
            relevant_columns.setdefault(lineage_urn, set()).update(
                column.casefold() for column in columns if isinstance(column, str) and column
            )
        for dataset_urn, page in pages:
            for assertion in page.assertions:
                assertion_urn = assertion.get("urn")
                if not isinstance(assertion_urn, str) or not assertion_urn.startswith(
                    "urn:li:assertion:"
                ):
                    continue
                fields = _assertion_field_paths(assertion)
                known_columns = relevant_columns.get(dataset_urn, set())
                if fields:
                    if not known_columns:
                        if assertion_status is EvidenceStatus.COMPLETE:
                            assertion_status = EvidenceStatus.AMBIGUOUS
                        reasons.append("assertions.column_lineage_unknown")
                    elif fields.isdisjoint(known_columns):
                        continue
                assertions_by_dataset.setdefault(dataset_urn, set()).add(assertion_urn)
                assertion_names[assertion_urn] = _find_first_string(
                    assertion, ("description", "name")
                )
                assertion_refs[assertion_urn] = f"graphql-assertions:{page.digest}"
                if assertion_urn not in recorded_assertions:
                    records.append(
                        EvidenceRecord(
                            id=f"graphql-assertion:{assertion_urn}",
                            kind=EvidenceKind.ASSERTION,
                            status=assertion_status,
                            source="DataHub GraphQL dataset.assertions",
                            detail=f"dataset={dataset_urn}",
                            critical=True,
                        )
                    )
                    recorded_assertions.add(assertion_urn)
        aggregate = ":".join(sorted(page.digest for _, page in pages)) or "none"
        assertion_count = sum(len(urns) for urns in assertions_by_dataset.values())
        records.append(
            EvidenceRecord(
                id=f"graphql-assertions:{aggregate}",
                kind=EvidenceKind.ASSERTION,
                status=assertion_status,
                source="DataHub GraphQL dataset.assertions",
                detail=f"datasets={len(pages)} assertions={assertion_count}",
                critical=True,
            )
        )

        enriched_impacted: list[ImpactedAsset] = []
        for asset in impacted:
            linked = tuple(sorted(assertions_by_dataset.get(asset.urn, set())))
            if not linked:
                enriched_impacted.append(asset)
                continue
            enriched_impacted.append(
                asset.model_copy(
                    update={
                        "assertion_urns": linked,
                        "evidence_refs": tuple(
                            sorted(
                                {
                                    *asset.evidence_refs,
                                    *(assertion_refs[urn] for urn in linked),
                                }
                            )
                        ),
                    }
                )
            )

        source_assertion_assets = tuple(
            ImpactedAsset(
                urn=assertion_urn,
                asset_type=AssetType.ASSERTION,
                name=assertion_names[assertion_urn],
                hop_count=1,
                owners=None,
                assertion_urns=(assertion_urn,),
                critical_asset=None,
                sensitive_data=None,
                direct_column_lineage=None,
                evidence_refs=(assertion_refs[assertion_urn],),
            )
            for assertion_urn in sorted(assertions_by_dataset.get(source_urn, set()))
        )
        return tuple(enriched_impacted), source_assertion_assets, assertion_status
