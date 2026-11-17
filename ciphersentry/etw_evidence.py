"""Read-only adapter for CipherSentry's experimental live ETW CSV format.

Stage 5.5C: parse and scope observations WITHOUT asserting originating-process
identity, generating file modifications, scoring ransomware, or containing PIDs.

This is an evidence-ingestion boundary, not a live transport or RiskEngine input.
The ETW 'reported_pid' is metadata of the event, NOT verified writer identity.
"""
from __future__ import annotations

import argparse
import csv
import ntpath
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

COLUMNS = frozenset({
    "kind", "event_time_utc", "callback_time_utc", "reported_pid",
    "file_key", "file_object", "io_size", "filename", "details",
})
HEX_KEY = re.compile(r"^0x[0-9a-fA-F]{1,16}$")


@dataclass(frozen=True)
class EtwWriteEvidence:
    """Single observed write. Neither filename nor PID is independently validated."""

    event_time_utc: datetime
    callback_time_utc: datetime
    reported_pid: int
    file_key: str
    file_object: str
    io_size: int
    filename: str | None
    reader_prior_key_candidate: bool

    @property
    def callback_delay_ms(self) -> float:
        return (self.callback_time_utc - self.event_time_utc).total_seconds() * 1000.0

    @property
    def process_attribution(self) -> str:
        # In particular, don't guess a creator for PID 4 or promote the
        # event-header PID into verified attribution to the original writer.
        return "unknown" if self.reported_pid <= 4 else "unverified_event_pid"


def _utc_timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid ETW timestamp: {value!r}") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("ETW timestamp must include a UTC offset")
    return result


def parse_write(row: dict[str, str]) -> EtwWriteEvidence:
    """Parse a Write row; never convert it directly into a RiskEngine FileEvent."""
    if row.get("kind") != "Write":
        raise ValueError("Only Write rows can be parsed as write evidence")
    try:
        pid = int(row["reported_pid"])
        size = int(row["io_size"])
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("Invalid reported PID or I/O size") from exc
    if pid < -1 or size < 0:
        raise ValueError("Invalid reported PID or negative I/O size")
    key = row.get("file_key") or ""
    file_object = row.get("file_object") or ""
    if not HEX_KEY.fullmatch(key) or not HEX_KEY.fullmatch(file_object):
        raise ValueError("Invalid ETW file key or file object")
    details = row.get("details") or ""
    if details not in {"reader-prior-key-candidate", "no-reader-prior-key-candidate"}:
        raise ValueError("Unexpected filename candidate field")
    return EtwWriteEvidence(
        event_time_utc=_utc_timestamp(row["event_time_utc"]),
        callback_time_utc=_utc_timestamp(row["callback_time_utc"]),
        reported_pid=pid,
        file_key=key,
        file_object=file_object,
        io_size=size,
        filename=(row.get("filename") or "").strip() or None,
        reader_prior_key_candidate=details == "reader-prior-key-candidate",
    )


def _absolute_windows_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or not ntpath.isabs(value):
        raise ValueError("The monitored root must be an absolute Windows path")
    return ntpath.normcase(ntpath.normpath(value))


def is_within_root(path: str | None, root: str) -> bool:
    """Lexical, case-insensitive path boundary; not symlink/path provenance proof."""
    if not path or not ntpath.isabs(path):
        return False
    candidate = ntpath.normcase(ntpath.normpath(path))
    try:
        return ntpath.commonpath([root, candidate]) == root
    except ValueError:  # Different drives or malformed paths.
        return False


def iter_writes(csv_path: str | Path) -> Iterator[EtwWriteEvidence]:
    """Stream writes from a trusted local capture file without materializing all rows."""
    with Path(csv_path).open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not COLUMNS.issubset(reader.fieldnames):
            raise ValueError("ETW CSV lacks required collector columns")
        for index, row in enumerate(reader, 2):
            if row.get("kind") != "Write":
                continue
            try:
                yield parse_write(row)
            except ValueError as exc:
                raise ValueError(f"Invalid ETW Write record on CSV line {index}: {exc}") from exc


@dataclass(frozen=True)
class EtwScopeSummary:
    total_write_callbacks: int
    filename_present: int
    named_writes_in_scope: int
    reader_prior_candidates_in_scope: int
    system_pid_writes_in_scope: int
    unverified_pid_writes_in_scope: int


def summarize_scope(csv_path: str | Path, monitored_root: str) -> EtwScopeSummary:
    """Count named writes in scope; unnamed writes cannot safely be scoped."""
    root = _absolute_windows_path(monitored_root)
    total = named = scoped = candidates = system = unverified = 0
    for event in iter_writes(csv_path):
        total += 1
        if event.filename is None:
            continue
        named += 1
        if not is_within_root(event.filename, root):
            continue
        scoped += 1
        candidates += int(event.reader_prior_key_candidate)
        system += int(event.reported_pid == 4)
        unverified += int(event.process_attribution == "unverified_event_pid")
    return EtwScopeSummary(total, named, scoped, candidates, system, unverified)


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only summary of a live ETW CSV capture")
    parser.add_argument("--csv", required=True, type=Path, help="Existing collector CSV")
    parser.add_argument("--root", required=True, help="Absolute Windows folder monitored")
    args = parser.parse_args()
    result = summarize_scope(args.csv, args.root)
    print("=== CipherSentry Stage 5.5C: ETW Evidence Bridge (read-only) ===")
    print(f"Total Write callbacks: {result.total_write_callbacks}")
    print(f"Write callbacks with filenames: {result.filename_present}")
    print(f"Named writes under chosen root: {result.named_writes_in_scope}")
    print(f"Reader-prior FileKey candidates in root: {result.reader_prior_candidates_in_scope}")
    print(f"System PID 4 writes in root: {result.system_pid_writes_in_scope}")
    print(f"Non-system reported-PID writes in root (UNVERIFIED): {result.unverified_pid_writes_in_scope}")
    print("No file writes performed; no risk scoring; no process containment.")
    print("Unresolved filenames cannot be assigned to this root by path alone.")


if __name__ == "__main__":
    main()
