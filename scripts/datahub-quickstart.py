#!/usr/bin/env python3
"""Prepare or verify the pinned loopback-only DataHub quickstart."""

from __future__ import annotations

import argparse
from pathlib import Path

from lineageguard.datahub.quickstart import (
    QuickstartNotRunning,
    QuickstartSecurityError,
    prepare_loopback_compose,
    stop_running_datahub,
    verify_local_docker_endpoint,
    verify_running_datahub_bindings,
    verify_startup_project_ownership,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    prepare = subcommands.add_parser("prepare")
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--refresh", action="store_true")
    subcommands.add_parser("verify-running")
    subcommands.add_parser("verify-local-endpoint")
    subcommands.add_parser("verify-startup")
    subcommands.add_parser("stop-running")
    args = parser.parse_args()

    try:
        if args.command == "prepare":
            destination = prepare_loopback_compose(args.output, refresh=args.refresh)
            print(f"Prepared checksum-pinned loopback DataHub Compose file at {destination}.")
        elif args.command == "verify-running":
            count = verify_running_datahub_bindings()
            print(f"PASS: {count} healthy DataHub containers publish only to loopback.")
        elif args.command == "verify-local-endpoint":
            verify_local_docker_endpoint()
            print("PASS: Docker uses a local Unix socket.")
        elif args.command == "verify-startup":
            count = verify_startup_project_ownership()
            print(f"PASS: {count} existing reserved-project containers are owner-verified.")
        elif args.command == "stop-running":
            count = stop_running_datahub()
            print(f"Stopped {count} running DataHub containers without deleting data.")
        else:
            raise AssertionError(f"unhandled command: {args.command}")
    except QuickstartNotRunning as exc:
        raise SystemExit(f"DataHub quickstart is stopped: {exc}") from None
    except QuickstartSecurityError as exc:
        raise SystemExit(f"DataHub quickstart security check failed: {exc}") from None


if __name__ == "__main__":
    main()
