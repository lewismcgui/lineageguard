"""Narrow GraphQL adapter for assertion context absent from stable MCP 0.6.0."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from lineageguard.config import Settings

DATASET_ASSERTIONS_QUERY = """
query LineageGuardDatasetAssertions($urn: String!, $start: Int!, $count: Int!) {
  dataset(urn: $urn) {
    assertions(start: $start, count: $count) {
      start
      count
      total
      assertions {
        urn
        info {
          type
          description
          datasetAssertion {
            datasetUrn
            fields { urn path }
            nativeType
            logic
          }
          source { type }
        }
      }
    }
  }
}
""".strip()


class GraphQLError(RuntimeError):
    """DataHub's GraphQL gap adapter could not prove assertion context."""


@dataclass(frozen=True, slots=True)
class AssertionPage:
    """One normalized page of assertions with an evidence digest."""

    assertions: tuple[dict[str, Any], ...]
    total: int
    start: int
    count: int
    digest: str


class DataHubGraphQLClient:
    """Read-only, token-authenticated client limited to documented assertion fields."""

    def __init__(self, settings: Settings, *, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        self._transport = transport

    def get_dataset_assertions(
        self, dataset_urn: str, *, start: int = 0, count: int = 100
    ) -> AssertionPage:
        if not dataset_urn.startswith("urn:li:dataset:"):
            raise ValueError("dataset_urn must be a DataHub dataset URN")
        if start < 0 or not 1 <= count <= 1000:
            raise ValueError("invalid assertion pagination")

        token = self.settings.resolve_datahub_token()
        if token is None:
            raise GraphQLError("A DataHub token is required for assertion context")

        endpoint = f"{str(self.settings.datahub_gms_url).rstrip('/')}/api/graphql"
        try:
            with httpx.Client(
                transport=self._transport,
                timeout=self.settings.mcp_timeout_seconds,
                headers={"Authorization": f"Bearer {token}"},
                trust_env=False,
            ) as client:
                response = client.post(
                    endpoint,
                    json={
                        "query": DATASET_ASSERTIONS_QUERY,
                        "variables": {"urn": dataset_urn, "start": start, "count": count},
                    },
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise GraphQLError("DataHub assertion query failed") from exc

        if not isinstance(payload, Mapping):
            raise GraphQLError("DataHub returned an invalid assertion response")
        if payload.get("errors"):
            raise GraphQLError("DataHub rejected the assertion query")
        try:
            connection = payload["data"]["dataset"]["assertions"]
            assertions = connection["assertions"]
            total = connection["total"]
            returned_start = connection["start"]
            returned_count = connection["count"]
        except (KeyError, TypeError) as exc:
            raise GraphQLError("DataHub returned an invalid assertion response") from exc
        if (
            not isinstance(total, int)
            or isinstance(total, bool)
            or total < 0
            or not isinstance(returned_start, int)
            or isinstance(returned_start, bool)
            or returned_start != start
            or not isinstance(returned_count, int)
            or isinstance(returned_count, bool)
            or not isinstance(assertions, list)
            or returned_count != len(assertions)
            or returned_count > count
            or start + returned_count > total
        ):
            raise GraphQLError("DataHub returned malformed assertions")
        urns: set[str] = set()
        for assertion in assertions:
            urn = assertion.get("urn") if isinstance(assertion, dict) else None
            if not isinstance(urn, str) or not urn.startswith("urn:li:assertion:") or urn in urns:
                raise GraphQLError("DataHub returned malformed assertions")
            info = assertion.get("info")
            dataset_assertion = info.get("datasetAssertion") if isinstance(info, Mapping) else None
            if isinstance(dataset_assertion, Mapping):
                assertion_dataset = dataset_assertion.get("datasetUrn")
                if assertion_dataset is not None and assertion_dataset != dataset_urn:
                    raise GraphQLError("DataHub returned malformed assertions")
            urns.add(urn)

        canonical = json.dumps(
            {
                "assertions": assertions,
                "count": returned_count,
                "start": returned_start,
                "total": total,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return AssertionPage(
            assertions=tuple(assertions),
            total=total,
            start=returned_start,
            count=returned_count,
            digest=hashlib.sha256(canonical).hexdigest(),
        )
