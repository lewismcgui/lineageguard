#!/usr/bin/env python3
"""Create a private PAT for the local DataHub quickstart without printing it."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from lineageguard.datahub.token import (
    TokenBootstrapError,
    create_private_local_token,
    ensure_local_token,
)


def _login_credentials() -> tuple[str, str]:
    """Resolve the local login without putting its password in argv or a file."""

    username = os.environ.get("DATAHUB_LOCAL_USERNAME", "datahub").strip()
    password = os.environ.get("DATAHUB_LOCAL_PASSWORD")
    if password is None:
        if not sys.stdin.isatty():
            raise TokenBootstrapError(
                "Set DATAHUB_LOCAL_PASSWORD for non-interactive local token creation"
            )
        password = getpass.getpass("Local DataHub quickstart password: ")
    if not username or not password:
        raise TokenBootstrapError("Local DataHub login credentials must not be blank")
    return username, password


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gms-url", default="http://127.0.0.1:8080")
    parser.add_argument("--frontend-url", default="http://127.0.0.1:9002")
    parser.add_argument("--output", type=Path, default=Path(".lineageguard/datahub-token"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--force", action="store_true")
    mode.add_argument("--ensure", action="store_true")
    args = parser.parse_args()

    try:
        if args.ensure or args.force:
            result = ensure_local_token(
                args.output,
                args.gms_url,
                args.frontend_url,
                credential_provider=_login_credentials,
                force=args.force,
            )
            print(
                f"Local DataHub token {result.status.value.casefold()} at {result.path}; "
                "token value not displayed."
            )
            return

        result = create_private_local_token(
            args.output,
            args.frontend_url,
            credential_provider=_login_credentials,
        )
    except TokenBootstrapError as exc:
        raise SystemExit(f"Token bootstrap failed: {exc}") from None
    print(f"Created private local DataHub token at {result.path}; token value not displayed.")


if __name__ == "__main__":
    main()
