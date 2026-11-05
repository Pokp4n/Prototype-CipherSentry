"""Controlled workloads that only modify fixtures in a freshly created directory.

This is a behavioural demonstration, not ransomware: no encryption, privilege
changes, persistence, discovery of user files, or recovery claims are involved.
The high-entropy payload is deterministic pseudorandom test data.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import queue
import sys
import tempfile
import threading
import time
import zipfile
from dataclasses import asdict
from pathlib import Path

import psutil

from .engine import FileEvent, shannon_entropy


MARKER = ".ciphersentry-lab-owned"


def _emit(payload: dict) -> None:
    print(json.dumps(payload), flush=True)


def _fixture_text(index: int, revision: int = 0) -> bytes:
    sentence = (
        f"CipherSentry disposable research fixture {index:04d}. Revision {revision}. "
        "This generated text contains no personal data. Behavioural lab activity.\n"
    )
    return (sentence * 48).encode("utf-8")


class _ParentSession:
    """Pipe ownership is separate from OS identity; EOF cancels managed work."""

    def __init__(self) -> None:
        self.commands: queue.Queue[str] = queue.Queue()
        self.closed = threading.Event()
        threading.Thread(target=self._read, daemon=True, name="lab-parent-pipe").start()

    def _read(self) -> None:
        for line in sys.stdin:
            self.commands.put(line.strip())
            if line.strip() == "finish":
                break
        self.closed.set()
        self.commands.put("")

    def wait_for(self, command: str) -> None:
        try:
            received = self.commands.get(timeout=15)
        except queue.Empty as exc:
            raise RuntimeError("Parent handshake timed out; stopping the workload.") from exc
        if received != command:
            raise RuntimeError("Parent did not authorize the workload; stopping.")


def run_workload(scenario: str, workspace: Path, files: int = 60, delay: float = 0.08,
                 *, managed: bool = False) -> dict:
    if scenario not in {"suspicious", "benign", "compression"}:
        raise ValueError("Scenario must be suspicious, benign, or compression.")
    if not 1 <= files <= 1000:
        raise ValueError("The lab supports 1 to 1000 generated files per run.")
    if not 0.01 <= delay <= 5.0:
        raise ValueError("Delay must be between 0.01 and 5 seconds.")
    workspace = Path(workspace).absolute()
    if workspace.is_symlink() or workspace.resolve() != workspace:
        raise ValueError("The lab workspace must be a real directory, not a symbolic link.")
    workspace.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="ciphersentry-run-", dir=workspace))
    marker = root / MARKER
    marker.write_text(json.dumps({"kind": "CipherSentry disposable fixtures", "pid": os.getpid(), "created": time.time()}), encoding="utf-8")
    fixtures: list[Path] = []
    for index in range(files):
        folder = root / f"department-{index % 4 + 1}"
        folder.mkdir(exist_ok=True)
        fixture = folder / f"sample-{index:04d}.txt"
        # Exclusive creation protects against an accidental pre-existing file.
        with fixture.open("xb") as handle:
            handle.write(_fixture_text(index))
        fixtures.append(fixture)
    identity = {"pid": os.getpid(), "create_time": psutil.Process().create_time()}
    session = _ParentSession() if managed else None
    _emit({"type": "ready", "root": str(root), "total": files, "scenario": scenario, **identity})
    if session is not None:
        # Remain alive and idle until the parent independently verifies OS identity.
        session.wait_for("start")
    else:
        time.sleep(max(0.15, delay))
    started = time.monotonic()
    generator = random.Random(4321)
    completed = 0
    for index, fixture in enumerate(fixtures):
        if session is not None and session.closed.is_set():
            raise RuntimeError("Parent pipe closed; stopping the workload.")
        if not marker.is_file() or root.is_symlink() or fixture.is_symlink() or fixture.parent.is_symlink():
            raise RuntimeError("Lab fixture ownership changed; stopping the workload.")
        if fixture.resolve().parent != fixture.parent or not fixture.is_file():
            raise RuntimeError("A fixture path changed; stopping the workload.")
        before = shannon_entropy(fixture.read_bytes())
        if scenario == "suspicious":
            payload = generator.randbytes(8192)
            fixture.write_bytes(payload)
            destination = fixture.with_suffix(".locked-demo")
            if destination.exists():
                raise RuntimeError("Refusing to replace an existing destination.")
            fixture.rename(destination)
            path = destination
            operation = "moved"
        elif scenario == "compression":
            path = fixture.with_suffix(".zip")
            # Standard-library archive creation is a legitimate workload. Keep
            # originals; a newly created archive has no previous entropy sample.
            with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.write(fixture, arcname=fixture.name)
            payload = path.read_bytes()
            before = None
            operation = "created"
        else:
            payload = _fixture_text(index, revision=1)
            fixture.write_bytes(payload)
            path = fixture
            operation = "modified"
        completed += 1
        event = FileEvent(
            timestamp=time.time(),
            path=str(path),
            operation=operation,
            pid=os.getpid(),
            process_name="CipherSentry lab worker",
            entropy_before=before,
            entropy_after=shannon_entropy(payload),
            source="lab",
        )
        _emit({"type": "event", "event": asdict(event), "completed": completed, "total": files, **identity})
        if session is not None:
            session.closed.wait(delay)
        else:
            time.sleep(delay)
    result = {"type": "complete", "completed": completed, "total": files, "elapsed": round(time.monotonic() - started, 4), "root": str(root), "scenario": scenario, **identity}
    _emit(result)
    if session is not None:
        # Keep OS metadata available while the parent validates buffered evidence.
        session.wait_for("finish")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["suspicious", "benign", "compression"], required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--files", type=int, default=60)
    parser.add_argument("--delay", type=float, default=0.08)
    parser.add_argument("--managed", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        run_workload(args.scenario, args.workspace, args.files, args.delay, managed=args.managed)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Lab error: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
