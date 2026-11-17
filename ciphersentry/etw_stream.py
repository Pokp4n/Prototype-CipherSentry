"""Read-only, incremental JSON Lines consumer for experimental ETW write evidence.

Stage 5.5E.1: this module does not start ETW, modify files, call RiskEngine,
resolve process identities, or authorize containment. The producer must emit
one validated Write event per JSON line using the schema below.

The event-header PID is not verified attribution to the originating writer.
"""
from __future__ import annotations

import argparse
import json
import ntpath
import sys
from dataclasses import dataclass
from typing import TextIO

from .etw_evidence import EtwWriteEvidence, is_within_root, parse_write

SCHEMA_VERSION = 1
MAX_LINE_CHARS = 65536
WRITE_FIELDS = frozenset({
    "schema", "kind", "event_time_utc", "callback_time_utc", "reported_pid",
    "file_key", "file_object", "io_size", "filename", "details",
})


@dataclass(frozen=True)
class StreamSummary:
    write_events_received: int
    named_writes_in_root: int
    system_pid_writes_in_root: int
    non_system_pid_writes_in_root: int
    reader_prior_candidates_in_root: int


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def parse_stream_line(line: str) -> EtwWriteEvidence:
    """Strictly validate one versioned JSONL record. Fail closed on bad evidence."""
    if len(line) > MAX_LINE_CHARS:
        raise ValueError("ETW JSONL record exceeds size limit")
    try:
        record = json.loads(line, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("Invalid ETW JSONL record") from exc
    if not isinstance(record, dict) or set(record) != WRITE_FIELDS:
        raise ValueError("ETW JSONL record has missing or unexpected fields")
    if type(record["schema"]) is not int or record["schema"] != SCHEMA_VERSION:
        raise ValueError("Unsupported ETW stream schema")
    if record["kind"] != "Write":
        raise ValueError("Only Write evidence is accepted")
    for field in ("reported_pid", "io_size"):
        if type(record[field]) is not int:
            raise ValueError(f"{field} must be a JSON integer")
    for field in ("event_time_utc", "callback_time_utc", "file_key", "file_object", "details"):
        if not isinstance(record[field], str):
            raise ValueError(f"{field} must be a string")
    if record["filename"] is not None and not isinstance(record["filename"], str):
        raise ValueError("filename must be a string or null")
    row = {key: (str(value) if key in {"reported_pid", "io_size"} else value)
           for key, value in record.items() if key != "schema"}
    return parse_write(row)


def consume_stream(source: TextIO, root: str, *, show_first: int = 5,
                   output: TextIO | None = None) -> StreamSummary:
    """Process JSONL incrementally, counting scoped observations only.

    A line with a non-Write kind, wrong schema, or malformed data is an error.
    The calling process should not use an incomplete summary for decisions.
    """
    if output is None:
        output = sys.stdout
    if not isinstance(root, str) or not ntpath.isabs(root):
        raise ValueError("Monitored root must be an absolute Windows path")
    if type(show_first) is not int or show_first < 0 or show_first > 50:
        raise ValueError("show_first must be an integer between 0 and 50")
    normalized_root = ntpath.normcase(ntpath.normpath(root))
    total = scoped = system = nonsystem = candidates = shown = 0
    for line_number, line in enumerate(source, start=1):
        if not line.strip():
            raise ValueError(f"Blank ETW JSONL record on line {line_number}")
        try:
            event = parse_stream_line(line)
        except ValueError as exc:
            raise ValueError(f"Invalid ETW JSONL line {line_number}: {exc}") from exc
        total += 1
        if not is_within_root(event.filename, normalized_root):
            continue
        scoped += 1
        system += int(event.reported_pid == 4)
        nonsystem += int(event.process_attribution == "unverified_event_pid")
        candidates += int(event.reader_prior_key_candidate)
        if shown < show_first:
            shown += 1
            print(f"[LIVE observation {scoped}] filename={ntpath.basename(event.filename or '')!r} "
                  f"reported_pid={event.reported_pid} ({event.process_attribution}); "
                  f"callback_delay_ms={event.callback_delay_ms:.2f}",
                  file=output, flush=True)
    return StreamSummary(total, scoped, system, nonsystem, candidates)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only ETW JSONL evidence receiver")
    parser.add_argument("--root", required=True, help="Monitored absolute Windows root")
    parser.add_argument("--show-first", type=int, default=5, help="Show first N in-scope observations (0-50)")
    args = parser.parse_args()
    print("=== CipherSentry Stage 5.5E: LIVE ETW evidence receiver (read-only) ===", flush=True)
    try:
        summary = consume_stream(sys.stdin, args.root, show_first=args.show_first)
    except (ValueError, UnicodeError, OSError) as exc:
        print(f"ETW stream rejected: {exc}", file=sys.stderr)
        return 2
    print("\n=== Live ETW Receiver Summary ===")
    print(f"Write records received: {summary.write_events_received}")
    print(f"Named writes in monitored root: {summary.named_writes_in_root}")
    print(f"System PID 4 writes in root: {summary.system_pid_writes_in_root}")
    print(f"Non-system event PIDs in root (UNVERIFIED): {summary.non_system_pid_writes_in_root}")
    print(f"Reader-prior FileKey candidates in root: {summary.reader_prior_candidates_in_root}")
    print("Risk scoring: NOT CONNECTED. Containment: DISABLED for ETW evidence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
