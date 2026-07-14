#!/usr/bin/env python3
"""UPSERT or offline-validate the deterministic Acme DataHub demo seed."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from lineageguard.config import Settings
from lineageguard.datahub.demo_seed import build_demo_mcps, seed_demo


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate the metadata plan without connecting to DataHub",
    )
    args = parser.parse_args()

    if args.validate_only:
        proposals = build_demo_mcps()
        if not all(proposal.validate() for proposal in proposals):
            print("DataHub demo seed validation failed.", file=sys.stderr)
            return 1
        print(f"Validated {len(proposals)} deterministic DataHub proposals offline.")
        return 0

    project_root = Path(__file__).resolve().parents[1]
    settings = Settings(_env_file=project_root / ".env", project_root=project_root)
    try:
        count = seed_demo(settings)
    except Exception as exc:
        # Deliberately omit exception text: third-party HTTP errors must never echo a token.
        print(
            f"DataHub demo seed failed ({type(exc).__name__}); no credential was displayed.",
            file=sys.stderr,
        )
        return 1
    print(f"Upserted {count} deterministic DataHub proposals.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
