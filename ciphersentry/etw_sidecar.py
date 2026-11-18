"""Locate a packaged ETW sidecar without starting it.

This module performs file discovery only. It does not elevate
privileges, create ETW sessions, score risk, or control processes.
"""

from dataclasses import dataclass
from pathlib import Path
import sys

COLLECTOR_RELATIVE_PATH = r"etw\LiveEtwStreamer.exe"

FILE_FOUND = "found"
FILE_UNAVAILABLE = "unavailable"
FILE_NOT_CHECKED = "not_checked"


@dataclass(frozen=True)
class CollectorReadiness:
    """What CipherSentry knows about the optional ETW collector file.

    ``file_state`` describes only whether the expected file exists in a
    packaged layout. A found file is not hash-verified, not trusted, and not
    known to work. This application never starts live ETW collection, and
    ETW process IDs are always unverified candidates.
    """

    file_state: str
    detail: str
    collector_path: Path | None = None
    collection_started: bool = False
    attribution_verified: bool = False

    @property
    def file_found(self) -> bool:
        return self.file_state == FILE_FOUND


def collector_readiness(
    application_executable: str | Path | None = None,
) -> CollectorReadiness:
    """Report ETW collector file availability without running anything.

    Uses ``find_packaged_collector`` and only inspects file metadata. The
    collector is never executed, and no ETW session or elevation is requested.
    """
    if application_executable is None and not getattr(sys, "frozen", False):
        return CollectorReadiness(
            FILE_NOT_CHECKED,
            "Running from Python source; collector discovery applies to the packaged app only.",
        )
    try:
        collector = find_packaged_collector(application_executable)
    except (OSError, ValueError) as exc:
        return CollectorReadiness(
            FILE_UNAVAILABLE, f"Collector location could not be checked ({type(exc).__name__}).")
    if collector is None:
        return CollectorReadiness(
            FILE_UNAVAILABLE,
            f"{COLLECTOR_RELATIVE_PATH} was not found beside CipherSentry.exe.",
        )
    return CollectorReadiness(
        FILE_FOUND,
        f"{COLLECTOR_RELATIVE_PATH} is present beside CipherSentry.exe. "
        "It has not been verified, trusted, or run.",
        collector,
    )


def find_packaged_collector(
    application_executable: str | Path | None = None,
) -> Path | None:
    """Find the ETW executable in a CipherSentry distribution.

    Without an explicit path, discovery is only enabled when running
    as a frozen application. The current working directory is never
    used to locate the collector.

    Returns None if the expected executable is unavailable.
    """
    if application_executable is None:
        if not getattr(sys, "frozen", False):
            return None
        application_executable = sys.executable

    application = Path(application_executable)

    if not application.is_absolute():
        raise ValueError("Application executable path must be absolute")

    if application.name.casefold() != "ciphersentry.exe":
        return None

    collector_dir = application.parent / "etw"
    collector = collector_dir / "LiveEtwStreamer.exe"

    if not application.is_file() or application.is_symlink():
        return None

    if collector_dir.is_symlink() or collector.is_symlink():
        return None

    if not collector.is_file():
        return None

    return collector
