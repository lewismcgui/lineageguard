"""Schema change extraction public API."""

from lineageguard.changes.parser import (
    ChangeParseError,
    ChangeParser,
    ManifestInput,
    UnsupportedChangeError,
    compare_dbt_manifests,
    parse_alter_table,
    parse_dbt_manifest_changes,
)

__all__ = [
    "ChangeParseError",
    "ChangeParser",
    "ManifestInput",
    "UnsupportedChangeError",
    "compare_dbt_manifests",
    "parse_alter_table",
    "parse_dbt_manifest_changes",
]
