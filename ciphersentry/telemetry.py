"""Small collector contract: capabilities are facts, not inferred coverage."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class CollectorCapabilities:
    name: str
    source: str
    operations: tuple[str, ...]
    process_attribution: bool
    process_context: bool
    write_payload: bool
    entropy_sampling: bool
    requires_administrator: bool
    limitations: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


WATCHDOG_CAPABILITIES = CollectorCapabilities(
    name="Watchdog directory notifications",
    source="folder",
    operations=("created", "modified", "moved", "deleted"),
    process_attribution=False,
    process_context=False,
    write_payload=False,
    entropy_sampling=True,
    requires_administrator=False,
    limitations=(
        "Notifications identify paths, not the process responsible for an operation.",
        "A modified notification is not a count of kernel write calls.",
        "Read operations and original write payloads are unavailable.",
        "Notifications can be combined, duplicated, delayed, or lost.",
        "Entropy samples the first 64 KiB after notification; it can miss partial changes.",
        "Folder read permissions are required; inaccessible paths reduce coverage.",
        "Initial baseline collection precedes observation and can race with external changes.",
    ),
)


@runtime_checkable
class MonitorProtocol(Protocol):
    """Replaceable lifecycle used by the controller, independent of watchdog."""

    capabilities: CollectorCapabilities

    @property
    def running(self) -> bool: ...

    @property
    def baseline_count(self) -> int: ...

    @property
    def dropped_events(self) -> int: ...

    def start(self) -> None: ...

    def stop(self) -> None: ...
