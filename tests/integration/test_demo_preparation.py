from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from lineageguard.demo import prepare_demo_projects

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_checked_in_demo_proves_green_baseline_and_breaking_proposal(tmp_path: Path) -> None:
    executable = shutil.which("dbt")
    assert executable is not None

    preparation = prepare_demo_projects(
        ROOT / "demo/acme_dbt",
        tmp_path / "workspace",
        dbt_executable=executable,
    )

    assert [command.exit_code for command in preparation.commands] == [0, 0, 1, 0]
    assert preparation.commands[2].expected_exit == "nonzero_breaking_pr"
    assert "order_total" in preparation.commands[2].output_tail.casefold()
    assert preparation.before_manifest.is_file()
    assert preparation.after_manifest.is_file()
