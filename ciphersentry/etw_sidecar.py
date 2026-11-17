"""Locate a packaged ETW sidecar without starting it.

This module performs file discovery only. It does not elevate
privileges, create ETW sessions, score risk, or control processes.
"""

from pathlib import Path
import sys


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
