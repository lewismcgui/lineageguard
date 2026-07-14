from __future__ import annotations

import json

import httpx
import pytest

from lineageguard.config import Settings
from lineageguard.datahub.graphql import DataHubGraphQLClient, GraphQLError


def _settings() -> Settings:
    return Settings(_env_file=None, datahub_gms_token="unit-test-token")


def test_assertion_query_is_narrow_authenticated_and_digested() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "data": {
                    "dataset": {
                        "assertions": {
                            "start": 0,
                            "count": 1,
                            "total": 1,
                            "assertions": [
                                {
                                    "urn": "urn:li:assertion:not-null-order-total",
                                    "runEvents": {"failed": 0, "succeeded": 1},
                                }
                            ],
                        }
                    }
                }
            },
        )

    client = DataHubGraphQLClient(_settings(), transport=httpx.MockTransport(handler))
    page = client.get_dataset_assertions(
        "urn:li:dataset:(urn:li:dataPlatform:duckdb,analytics.stg_orders,PROD)"
    )
    assert page.total == 1
    assert page.assertions[0]["urn"] == "urn:li:assertion:not-null-order-total"
    assert len(page.digest) == 64
    assert seen[0].headers["Authorization"] == "Bearer unit-test-token"
    body = json.loads(seen[0].content)
    assert body["variables"]["count"] == 100
    assert "runEvents" not in body["query"]


def test_graphql_error_is_fail_closed_without_leaking_details() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"errors": [{"message": "sensitive internals"}]})

    client = DataHubGraphQLClient(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(GraphQLError, match="rejected") as caught:
        client.get_dataset_assertions(
            "urn:li:dataset:(urn:li:dataPlatform:duckdb,analytics.stg_orders,PROD)"
        )
    assert "sensitive internals" not in str(caught.value)


def test_graphql_non_object_json_is_normalized_to_graphql_error() -> None:
    client = DataHubGraphQLClient(
        _settings(),
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=[])),
    )

    with pytest.raises(GraphQLError, match="invalid assertion response"):
        client.get_dataset_assertions(
            "urn:li:dataset:(urn:li:dataPlatform:duckdb,analytics.stg_orders,PROD)"
        )


def test_assertion_query_rejects_non_dataset_urn() -> None:
    client = DataHubGraphQLClient(_settings(), transport=httpx.MockTransport(lambda _: None))
    with pytest.raises(ValueError, match="dataset URN"):
        client.get_dataset_assertions("urn:li:dashboard:executive-revenue")


@pytest.mark.parametrize(
    "connection",
    [
        {"start": 0, "count": 0, "total": -1, "assertions": []},
        {"start": 1, "count": 0, "total": 0, "assertions": []},
        {
            "start": 0,
            "count": 1,
            "total": 1,
            "assertions": [{"urn": "not-an-assertion"}],
        },
        {
            "start": 0,
            "count": 2,
            "total": 2,
            "assertions": [
                {"urn": "urn:li:assertion:duplicate"},
                {"urn": "urn:li:assertion:duplicate"},
            ],
        },
        {
            "start": 0,
            "count": 1,
            "total": 1,
            "assertions": [
                {
                    "urn": "urn:li:assertion:wrong-dataset",
                    "info": {
                        "datasetAssertion": {
                            "datasetUrn": "urn:li:dataset:(other)",
                        }
                    },
                }
            ],
        },
    ],
)
def test_assertion_query_rejects_inconsistent_or_malformed_pages(connection) -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(200, json={"data": {"dataset": {"assertions": connection}}})
    )
    client = DataHubGraphQLClient(_settings(), transport=transport)

    with pytest.raises(GraphQLError, match="malformed"):
        client.get_dataset_assertions(
            "urn:li:dataset:(urn:li:dataPlatform:duckdb,analytics.stg_orders,PROD)"
        )
