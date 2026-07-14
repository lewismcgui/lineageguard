"""LineageGuard PR Agent."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("lineageguard-pr-agent")
except PackageNotFoundError:  # pragma: no cover - editable source fallback
    __version__ = "0.1.0"

__all__ = ["__version__"]
