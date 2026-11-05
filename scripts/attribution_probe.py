"""Compare an independent harmless writer with real folder observations.

Run from the checkout: python -m scripts.attribution_probe --output report.json
This tests the selected host's watchdog backend. It does not provide ETW or prove
Windows attribution when executed on another operating system.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import json
import os
from pathlib import Path
import platform
import queue
import statistics
import subprocess
import sys
import tempfile
import threading
import time

import psutil

from ciphersentry.attribution import collect_process_context
from ciphersentry.monitor import FolderMonitor
from ciphersentry.process_identity import OwnedProcessLaunch, ProcessIdentityError
from ciphersentry.telemetry import WATCHDOG_CAPABILITIES


MARKER = ".ciphersentry-attribution-probe"


def _handshake_line(stream, timeout: float = 10.0) -> str:
    """Bound the pipe handshake without relying on Windows pipe select()."""
    result = queue.Queue(maxsize=1)

    def read() -> None:
        try:
            result.put(stream.readline())
        except (OSError, ValueError) as error:
            result.put(error)

    threading.Thread(target=read, name="ciphersentry-probe-handshake", daemon=True).start()
    try:
        value = result.get(timeout=timeout)
    except queue.Empty as error:
        raise RuntimeError("Timed out waiting for the writer identity handshake.") from error
    if isinstance(value, Exception):
        raise RuntimeError("Writer identity handshake pipe failed.") from value
    return value


def _writer(root: Path, files: int) -> int:
    """Only touch the fresh fixtures described by the parent harness marker."""
    root = root.absolute()
    if root.resolve() != root or root.is_symlink():
        raise ValueError("Probe root must be a real directory.")
    marker = json.loads((root / MARKER).read_text(encoding="utf-8"))
    if marker != {"kind": "CipherSentry disposable attribution fixtures", "files": files}:
        raise ValueError("Probe ownership marker does not match this run.")
    fixtures = root / "fixtures"
    if fixtures.is_symlink():
        raise ValueError("Refusing symbolic-link fixtures.")
    process = psutil.Process()
    identity = {"pid": process.pid, "create_time": process.create_time()}
    print(json.dumps({"type": "ready", **identity}), flush=True)
    # The parent must independently verify our live OS identity before writes.
    # EOF, timeout, or any other command exits without modifying the fixtures.
    if _handshake_line(sys.stdin, timeout=15.0) != "start\n":
        raise RuntimeError("Writer identity was not approved; no fixtures modified.")
    for index in range(files):
        path = fixtures / f"dummy-{index:04d}.txt"
        if path.is_symlink() or path.read_bytes() != b"A" * 8192:
            raise ValueError("Probe fixture changed or is not owned dummy content.")
        started_wall = time.time()
        started_monotonic = time.monotonic()
        with path.open("wb") as handle:
            handle.write(bytes(range(256)) * 32)
            handle.flush()
            os.fsync(handle.fileno())
        print(json.dumps({
            "type": "operation", "path": str(path), "operation": "modified", **identity,
            "started_wall": started_wall, "started_monotonic": started_monotonic,
            "completed_wall": time.time(), "completed_monotonic": time.monotonic(),
        }), flush=True)
        time.sleep(.08)
    print(json.dumps({"type": "complete", "files": files}), flush=True)
    return 0


def summarize_observations(ground_truth: list[dict], observations: list[dict]) -> dict:
    """Match unique fixture modifications; never inject ground truth into events."""
    expected = {os.path.normcase(item["path"]): item for item in ground_truth}
    matching: dict[str, list[dict]] = {path: [] for path in expected}
    other_events = 0
    for observation in observations:
        key = os.path.normcase(observation["path"])
        if key in expected and observation["operation"] == "modified":
            matching[key].append(observation)
        else:
            other_events += 1
    correct = incorrect = unattributed = 0
    delivery_delays = []
    notification_delays = []
    for path, items in matching.items():
        if not items:
            continue
        truth = expected[path]
        earliest = min(items, key=lambda item: item["received_monotonic"])
        delivery_delays.append(earliest["received_monotonic"] - truth["started_monotonic"])
        if earliest.get("observed_at") is not None:
            notification_delays.append(earliest["observed_at"] - truth["started_wall"])
        for item in items:
            if item.get("pid") is None:
                unattributed += 1
            elif item["pid"] != truth["pid"]:
                incorrect += 1
            elif (item.get("process_context") or {}).get("create_time") != truth["create_time"]:
                # A matching PID with no stable process identity is insufficient.
                incorrect += 1
            else:
                correct += 1
    matched = sum(bool(items) for items in matching.values())
    observed_matching = sum(len(items) for items in matching.values())
    return {
        "expected_unique_file_modifications": len(expected),
        "observed_unique_file_modifications": matched,
        "missing_file_modifications": len(expected) - matched,
        "duplicate_modified_notifications": sum(max(0, len(items) - 1) for items in matching.values()),
        "matching_modified_notifications": observed_matching,
        "other_notifications": other_events,
        "file_modification_coverage": matched / len(expected) if expected else None,
        "correctly_attributed_notifications": correct,
        "incorrect_or_unstable_attribution_notifications": incorrect,
        "unattributed_notifications": unattributed,
        "attribution_coverage": (correct + incorrect) / observed_matching if observed_matching else None,
        "correct_attribution_fraction": correct / observed_matching if observed_matching else None,
        "delivery_delay_seconds": {
            "samples": delivery_delays,
            "median": statistics.median(delivery_delays) if delivery_delays else None,
            "maximum_observed": max(delivery_delays) if delivery_delays else None,
        },
        "notification_delay_seconds_wall_clock": notification_delays,
        "missing_paths": [path for path, items in matching.items() if not items],
    }


def run_attribution_probe(output: Path, files: int = 12, workspace: Path | None = None) -> dict:
    """Run the real collector independently of the child's ground-truth pipe."""
    if isinstance(files, bool) or not isinstance(files, int) or not 1 <= files <= 200:
        raise ValueError("Probe file count must be from 1 to 200.")
    if workspace is not None:
        workspace = Path(workspace).expanduser().absolute()
        if workspace.resolve() != workspace or workspace.is_symlink():
            raise ValueError("Workspace must be a real directory, not a symbolic link.")
        workspace.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="ciphersentry-attribution-", dir=workspace))
    (root / MARKER).write_text(json.dumps({"kind": "CipherSentry disposable attribution fixtures", "files": files}), encoding="utf-8")
    fixtures = root / "fixtures"
    fixtures.mkdir()
    for index in range(files):
        with (fixtures / f"dummy-{index:04d}.txt").open("xb") as handle:
            handle.write(b"A" * 8192)
    observations = []
    errors = []
    lock = threading.Lock()

    def observed(event) -> None:
        item = asdict(event)
        item["received_monotonic"] = time.monotonic()
        with lock:
            observations.append(item)

    monitor = FolderMonitor(fixtures, observed, errors.append)
    process = None
    worker = None
    try:
        monitor.start()
        arguments = ["-m", "scripts.attribution_probe", "--writer", str(root), "--files", str(files)]
        process = subprocess.Popen(
            [sys.executable, *arguments], stdin=subprocess.PIPE,
            cwd=str(Path(__file__).resolve().parent.parent), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        launch = OwnedProcessLaunch.capture(process.pid, arguments)
        ready = json.loads(_handshake_line(process.stdout))
        if not isinstance(ready, dict) or ready.get("type") != "ready":
            raise RuntimeError("Expected a writer identity handshake.")
        worker = launch.verify_worker(ready.get("pid"), ready.get("create_time"))
        context = collect_process_context(worker.pid, expected_create_time=worker.create_time)
        if (not context["identity_verified"] or context["pid"] != worker.pid
                or context["create_time"] != worker.create_time
                or context["parent_pid"] != worker.parent_pid
                or not context["executable"]
                or Path(context["executable"]).resolve() != Path(worker.executable).resolve()):
            raise RuntimeError("Independent writer metadata could not be verified.")
        worker.validate()
        stdout, stderr = process.communicate(input="start\n", timeout=max(15, files * .2 + 5))
        records = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        if process.returncode != 0:
            raise RuntimeError(f"Harmless writer failed: {stderr.strip()}")
        ground_truth = [item for item in records if item["type"] == "operation"]
        if len(ground_truth) != files or any(
            item["pid"] != worker.pid or item["create_time"] != worker.create_time for item in ground_truth
        ):
            raise RuntimeError("Writer ground-truth identity or operation count mismatch.")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with lock:
                snapshot = list(observations)
            if summarize_observations(ground_truth, snapshot)["missing_file_modifications"] == 0:
                time.sleep(.2)  # Allow trailing duplicate notifications to arrive.
                break
            time.sleep(.02)
    finally:
        if process is not None and process.poll() is None:
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()  # Refuse an unverified writer through its own pipe.
            if worker is not None:
                try:
                    worker.validate().terminate()
                except (ProcessIdentityError, psutil.Error):
                    # Never signal an unavailable or changed reported identity.
                    pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # Popen owns this exact launch handle, not a claimed worker PID.
                process.kill()
                process.wait(timeout=3)
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        monitor.stop()
    with lock:
        snapshot = list(observations)
    report = {
        "format_version": 1,
        "purpose": "Controlled harmless writer vs independent filesystem collector; not a ransomware benchmark",
        "recorded_at": time.time(), "platform": platform.platform(), "python": platform.python_version(),
        "collector": WATCHDOG_CAPABILITIES.to_dict(),
        "workspace": str(root), "fixtures_retained": True,
        "permissions": "Standard-user access to generated fixtures; no elevation requested.",
        "ground_truth_identity": ready, "independently_collected_process_context": context,
        "launch_pid": process.pid,
        "writer_identity_consistent": all(item["pid"] == ready["pid"] and item["create_time"] == ready["create_time"] for item in ground_truth),
        "baseline_count": monitor.baseline_count, "dropped_notifications": monitor.dropped_events,
        "metrics": summarize_observations(ground_truth, snapshot),
        "ground_truth": ground_truth, "observations": snapshot, "collector_errors": errors,
        "interpretation": "Watchdog cannot identify the writer. Ground-truth PID is for comparison only and is never assigned to collector events. Automatic process containment remains unsupported for this collector.",
        "measurement_limits": [
            "Coverage is per unique expected file modification, not per kernel write operation.",
            "Duplicate count is after collector filtering; raw kernel-event completeness is not measured.",
            "Delivery delay includes collector debounce, queueing, sampling and callback dispatch.",
            "Notification delay uses local wall-clock time and can be affected by clock adjustment.",
            "The probe tests only the operating system reported above; Windows results require a Windows run.",
        ],
    }
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--files", type=int, default=12)
    parser.add_argument("--writer", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.writer is not None:
        return _writer(args.writer, args.files)
    if args.output is None:
        parser.error("--output is required")
    report = run_attribution_probe(args.output, files=args.files, workspace=args.workspace)
    print(json.dumps({"report": str(args.output), "platform": report["platform"], "metrics": report["metrics"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
