"""Labelled behavioural-detection evaluation harness for CipherSentry.

Each run drives the real application pipeline headlessly (FolderMonitor ->
Controller -> frozen RiskEngine -> SQLite) against one labelled synthetic
workload executed by a separate harmless writer process, and records the
writer's independent ground truth. No GUI, lab worker, containment, ETW
collector or elevation is involved; the response mode is alert-only.

  python -m scripts.evaluate --output results-dir [--split heldout] [--repeats 1] [--policy m3-v1]
  python -m scripts.evaluate --list

--policy selects the detection-rule policy (default m3-v1, the Milestone 3
baseline). The selected version is recorded in every manifest, run and summary.

Results are synthetic-workload measurements of the current rules. They are
not ransomware detection accuracy.
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import replace
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import queue
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts import eval_metrics, eval_workloads  # noqa: E402
from scripts.eval_workloads import (  # noqa: E402
    DEFAULT_POLICY_VERSION, EVALUATION_POLICIES, LABEL_RULE, MARKER, MARKER_KIND, WorkloadSpec, policy_sha256,
)

# Format 2 adds the policy version to manifests, runs, summaries and the CSV.
# Format 1 records (the M3 pilot) have no policy version and used m3-v1.
FORMAT_VERSION = 2
FORBIDDEN_ACTIONS = {"lab_started", "lab_finished", "worker_suspended", "worker_resumed",
                     "worker_stopped", "etw_candidate_observation"}
QUIET_BEFORE_S = 1.0
SETTLE_MIN_S = 2.0
SETTLE_IDLE_S = 1.5
SETTLE_MAX_S = 20.0
CLOCK_TOLERANCE_S = 0.002


class PolicyMismatch(RuntimeError):
    pass


# --- environment ----------------------------------------------------------

def _git(*args: str) -> str | None:
    try:
        result = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def environment_info() -> dict:
    versions = {}
    for name in ("PySide6", "watchdog", "psutil"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    tracked_changes = _git("status", "--porcelain", "--untracked-files=no")
    return {
        "platform": platform.platform(), "machine": platform.machine(),
        "processor": platform.processor(), "logical_cpus": os.cpu_count(),
        "python": platform.python_version(), "packages": versions,
        "git_commit": _git("rev-parse", "HEAD"),
        "git_tracked_changes_present": bool(tracked_changes) if tracked_changes is not None else None,
        "clock": "time.perf_counter (QueryPerformanceCounter on Windows, system-wide) for latencies; "
                 "time.time only for wall-clock notification delay",
        "endpoint_security": "Not queried. Antivirus real-time scanning may add file I/O latency.",
        "privileges": "Standard user; no elevation requested.",
    }


# --- one run ---------------------------------------------------------------

def _pump(app, seconds: float) -> None:
    from PySide6.QtCore import QEventLoop
    end = time.perf_counter() + seconds
    while True:
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 20)
        if time.perf_counter() >= end:
            return
        time.sleep(0.005)


def _pump_until(app, predicate, timeout: float, what: str) -> None:
    from PySide6.QtCore import QEventLoop
    deadline = time.perf_counter() + timeout
    while not predicate():
        if time.perf_counter() > deadline:
            raise TimeoutError(f"Timed out waiting for {what}")
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 20)
        time.sleep(0.005)


def _reader(stream, sink: queue.Queue) -> None:
    for line in stream:
        sink.put(line)
    sink.put(None)


def _relative(path: str, root: Path) -> str:
    try:
        return Path(path).resolve(strict=False).relative_to(root).as_posix()
    except (ValueError, OSError):
        return path


def _signals(assessment) -> list[dict]:
    return [{"name": s.name, "points": s.points, "maximum": s.maximum, "value": s.value, "available": s.available}
            for s in assessment.signals]


def run_once(app, spec: WorkloadSpec, repeat: int, workspace: Path, *, keep_fixtures: bool = False,
             evidence_dir: Path | None = None, run_id: str = "",
             policy_version: str = DEFAULT_POLICY_VERSION) -> dict:
    from ciphersentry.controller import Controller

    selected = eval_workloads.evaluation_policy(policy_version)
    expected_policy = selected["policy"]
    seed = spec.seed * 1000 + repeat
    effective = replace(spec, seed=seed)
    result: dict = {
        "format_version": FORMAT_VERSION, "run_id": run_id, "workload_id": spec.workload_id,
        "family": spec.family, "label": spec.label, "split": spec.split, "repeat": repeat, "seed": seed,
        "params": spec.params, "policy_version": policy_version, "status": "failed", "error": None,
    }
    workspace.mkdir(parents=True, exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix="cs-eval-", dir=workspace)).resolve()
    (run_root / MARKER).write_text(json.dumps({"kind": MARKER_KIND, "run_id": run_id}), encoding="utf-8")
    watched = run_root / "watched"
    watched.mkdir()
    controller = None
    process = None
    captured: list[tuple[float, object, object]] = []
    app_errors: list[str] = []
    actions: list[dict] = []
    writer_stderr: list[str] = []
    lines: queue.Queue = queue.Queue()
    errors: queue.Queue = queue.Queue()
    try:
        fixtures = eval_workloads.create_fixtures(watched, effective)
        plan = eval_workloads.build_plan(effective)
        expected = eval_workloads.expected_observations(plan)
        (run_root / "plan.json").write_text(json.dumps({"seed": seed, "plan": plan}), encoding="utf-8")
        result["fixtures"] = len(fixtures)
        result["planned_actions"] = sum(len(step["actions"]) for step in plan)

        appdata = run_root / "appdata"
        if policy_version != DEFAULT_POLICY_VERSION:
            # m3-v1 runs use the app's built-in defaults exactly as in Milestone 3.
            # Other policies go through the app's own settings file, alert-only.
            appdata.mkdir()
            (appdata / "settings.json").write_text(json.dumps(
                {"schema_version": 2, "response_mode": "alert_only", "risk_config": expected_policy}), encoding="utf-8")
        controller = Controller(appdata)
        live_policy = controller.engine.config.to_dict()
        if live_policy != expected_policy:
            raise PolicyMismatch(f"Live risk policy differs from the selected {policy_version} evaluation policy: "
                                 f"{live_policy}")
        if controller.settings.get("response_mode") != "alert_only":
            raise RuntimeError("Evaluation requires alert-only response mode.")
        controller.event_received.connect(lambda event, assessment: captured.append((time.perf_counter(), event, assessment)))
        controller.error.connect(app_errors.append)
        controller.choose_folder(watched)
        controller.start_monitor()
        _pump_until(app, lambda: controller.monitoring, 60, "the monitoring baseline")
        baseline_ready = time.perf_counter()
        baseline_count = controller.monitor_health["baseline_count"]
        _pump(app, QUIET_BEFORE_S)
        pre_workload_events = len(captured)

        process = subprocess.Popen(
            [sys.executable, "-m", "scripts.evaluate", "--writer", str(run_root)], cwd=str(REPO),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        threading.Thread(target=_reader, args=(process.stdout, lines), daemon=True).start()
        threading.Thread(target=_reader, args=(process.stderr, errors), daemon=True).start()

        ready = None
        received_at = None
        complete = None
        deadline = time.perf_counter() + 30
        duration = sum(step["delay"] for step in plan)
        while complete is None:
            app.processEvents()
            try:
                line = lines.get(timeout=0.01)
            except queue.Empty:
                line = ""
            if line is None:
                break
            if line:
                record = json.loads(line)
                if record["type"] == "ready":
                    ready, received_at = record, time.perf_counter()
                    process.stdin.write("start\n")
                    process.stdin.flush()
                    deadline = time.perf_counter() + duration + 60
                elif record["type"] == "action":
                    actions.append(record)
                elif record["type"] == "complete":
                    complete = record
                elif record["type"] == "cancelled":
                    raise RuntimeError(f"Writer cancelled: {record.get('reason')}")
            if time.perf_counter() > deadline:
                raise TimeoutError("Workload writer did not complete in time")
        if complete is None:
            raise RuntimeError("Workload writer exited before completing")

        # Let notifications drain: at least SETTLE_MIN_S, then until the monitor
        # backlog is empty and no event arrived for SETTLE_IDLE_S (bounded).
        settle_start = time.perf_counter()
        last_count, last_change = len(captured), settle_start
        while True:
            _pump(app, 0.05)
            now = time.perf_counter()
            if len(captured) != last_count:
                last_count, last_change = len(captured), now
            pending = controller.monitor_health["pending"]
            if now - settle_start >= SETTLE_MIN_S and pending == 0 and now - last_change >= SETTLE_IDLE_S:
                break
            if now - settle_start >= SETTLE_MAX_S:
                result["settle_timed_out"] = True
                break
        window_end = time.perf_counter()
        health = controller.monitor_health

        # --- assemble the run record ------------------------------------
        clock_offset = received_at - ready["perf"]
        clock_ok = -CLOCK_TOLERANCE_S <= clock_offset <= 2.0
        t_start = actions[0]["started_perf"] if actions else None
        t_last_action = actions[-1]["completed_perf"] if actions else None
        in_window = [(t, e, a) for t, e, a in captured[pre_workload_events:]]
        scored = [(t, e, a) for t, e, a in in_window if a.level != "Unscored"]
        unscored = [(t, e, a) for t, e, a in in_window if a.level == "Unscored"]
        first_event = in_window[0] if in_window else None
        first_high = next(((t, e, a) for t, e, a in scored if a.level == "High"), None)
        first_uncertain = next(((t, e, a) for t, e, a in scored if a.level in {"Uncertain", "High"}), None)
        peak = max(scored, key=lambda item: item[2].score, default=None)
        max_level = ("High" if any(a.level == "High" for _, _, a in scored) else
                     "Uncertain" if any(a.level == "Uncertain" for _, _, a in scored) else
                     "Low" if scored else None)

        def since_start(value):
            return round(value - t_start, 4) if (value is not None and t_start is not None and clock_ok) else None

        root = controller.folder
        observed = [{"path": _relative(e.path, root), "operation": e.operation} for _, e, _ in in_window]
        comparable = sum(1 for _, e, _ in scored if e.entropy_before is not None and e.entropy_after is not None)
        stored = controller.store.recent_events(100_000)
        audit = controller.store.recent_actions(100_000)
        alerts = controller.store.recent_alerts(100_000)
        responses = [row.get("response") or {} for row in stored]
        safety = {
            "response_mode": controller.settings.get("response_mode"),
            # "Frozen" = fixed for this experiment: the selected policy version.
            "live_policy_matches_frozen": live_policy == expected_policy,
            "lab_worker_started": controller.process is not None,
            "forbidden_audit_actions": sorted({a["action"] for a in audit} & FORBIDDEN_ACTIONS),
            "containment_attempted": any(r.get("outcome") not in {None, "not_attempted"} or r.get("allowed")
                                         for r in responses),
            "etw_candidate_records": controller.etw_candidate_count,
            "etw_collection_started": controller.etw_readiness.collection_started,
        }
        safety["ok"] = (safety["response_mode"] == "alert_only" and safety["live_policy_matches_frozen"]
                        and not safety["lab_worker_started"] and not safety["forbidden_audit_actions"]
                        and not safety["containment_attempted"] and safety["etw_candidate_records"] == 0
                        and not safety["etw_collection_started"])
        result.update({
            "status": "completed" if safety["ok"] else "failed",
            "error": None if safety["ok"] else "Safety check failed; see 'safety'.",
            "max_level": max_level,
            "peak_score": peak[2].score if peak else None,
            "peak_signals": _signals(peak[2]) if peak else [],
            "peak_features": {k: peak[2].features.get(k) for k in (
                "modification_count", "unique_modified_files", "unique_modified_rate", "entropy_rise_files",
                "entropy_comparable_count", "modified_directories", "rename_suffix_files",
                "contributing_families")} if peak else {},
            "peak_missing_evidence": list(peak[2].missing_evidence) if peak else [],
            "first_high": ({"score": first_high[2].score, "signals": _signals(first_high[2])} if first_high else None),
            "level_counts": {level: sum(1 for _, _, a in in_window if a.level == level)
                             for level in ("High", "Uncertain", "Low", "Unscored")},
            "timings": {
                "clock_alignment_offset_s": round(clock_offset, 6), "clock_alignment_ok": clock_ok,
                "baseline_ready_to_start_s": round(t_start - baseline_ready, 4) if t_start else None,
                "workload_duration_s": since_start(t_last_action),
                "delivery_delay_s": since_start(first_event[0]) if first_event else None,
                "notification_delay_wall_s": (round(first_event[1].observed_at - actions[0]["started_wall"], 4)
                                              if first_event and actions and first_event[1].observed_at else None),
                "first_uncertain_or_high_latency_s": since_start(first_uncertain[0]) if first_uncertain else None,
                "detection_latency_s": since_start(first_high[0]) if first_high else None,
                "detected_after_workload_end": (first_high[0] > t_last_action) if first_high and t_last_action else None,
                "observation_window_s": since_start(window_end),
            },
            "coverage": eval_metrics.match_coverage(expected, observed),
            "evidence": {
                "baseline_files": baseline_count, "fixtures": len(fixtures),
                "baseline_complete": baseline_count == len(fixtures),
                "pre_workload_events": pre_workload_events,
                "events_in_window": len(in_window), "scored_events": len(scored),
                "late_observations": controller.late_observations, "unscored_events": len(unscored),
                "stale_events_ignored": controller.stale_events_ignored,
                "dropped_notifications": health["dropped_events"],
                "max_monitor_lag_s": round(health["max_lag_seconds"], 4),
                "entropy_comparable_fraction": eval_metrics.ratio(comparable, len(scored)),
                "alerts_recorded": len(alerts),
                "collector_warnings": [a["detail"] for a in audit if a["action"] == "error_or_unavailable_evidence"][:50],
                "app_errors": app_errors[:50],
            },
            "safety": safety,
            "ground_truth": {"fixtures": fixtures, "actions": actions, "expected_notifications": expected,
                             "writer_complete": complete},
            "observed_events": [{
                "path": _relative(e.path, root), "operation": e.operation,
                "received_s": since_start(t), "notification_wall_s": (round(e.observed_at - actions[0]["started_wall"], 4)
                                                                      if e.observed_at and actions else None),
                "entropy_before": e.entropy_before, "entropy_after": e.entropy_after,
                "level": a.level, "score": a.score} for t, e, a in in_window],
        })
        if evidence_dir is not None:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            controller.store.export_json(evidence_dir / f"{run_id}.json")
    except Exception as error:  # preserve the failure as a result, never discard it
        result["status"] = "failed"
        result["error"] = f"{type(error).__name__}: {error}"
        result["traceback"] = traceback.format_exc()
        result["partial_actions"] = actions
    finally:
        if process is not None:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()  # EOF cancels any remaining work
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()  # this run's own Popen handle only, never a PID lookup
                process.wait(timeout=5)
                result["writer_forced_kill"] = True
            result["writer_exit_code"] = process.returncode
            while True:
                try:
                    line = errors.get(timeout=1)
                except queue.Empty:
                    break
                if line is None:
                    break
                writer_stderr.append(line.rstrip())
            result["writer_stderr_tail"] = writer_stderr[-20:]
        if controller is not None:
            controller.stop_monitor()
            controller.close()
            _pump(app, 0.2)
        result["writer_running_after_cleanup"] = process is not None and process.poll() is None
        retain = keep_fixtures or result["status"] != "completed"
        if retain:
            result["fixtures_retained_at"] = str(run_root)
        else:
            _remove_run_root(run_root, workspace)
    return result


def _remove_run_root(run_root: Path, workspace: Path) -> None:
    """Delete only a marker-owned run directory inside the evaluation workspace."""
    run_root = run_root.resolve()
    if run_root.parent != workspace.resolve() or not run_root.name.startswith("cs-eval-"):
        raise RuntimeError(f"Refusing to delete unexpected directory: {run_root}")
    marker = json.loads((run_root / MARKER).read_text(encoding="utf-8"))
    if marker.get("kind") != MARKER_KIND:
        raise RuntimeError("Refusing to delete a directory without the evaluation marker")
    shutil.rmtree(run_root)


# --- experiment ------------------------------------------------------------

CSV_FIELDS = ["run_id", "workload_id", "label", "split", "repeat", "seed", "status", "max_level", "peak_score",
              "detection_latency_s", "delivery_delay_s", "workload_duration_s", "exact_coverage",
              "late_observations", "dropped_notifications", "error", "policy_version"]


def run_experiment(specs: list[WorkloadSpec], output: Path, *, repeats: int = 1, order_seed: int = 20261118,
                   workspace: Path | None = None, keep_fixtures: bool = False, export_evidence: bool = False,
                   app=None, progress=print, policy_version: str = DEFAULT_POLICY_VERSION) -> dict:
    from PySide6.QtCore import QCoreApplication

    selected = eval_workloads.evaluation_policy(policy_version)  # refuse unknown versions before any I/O
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"Output directory is not empty: {output}")
    if not 1 <= repeats <= 100:
        raise ValueError("repeats must be between 1 and 100")
    workspace = Path(workspace or Path(tempfile.gettempdir()) / "ciphersentry-eval").absolute()
    if workspace.resolve().is_relative_to(REPO) or output.resolve().is_relative_to(workspace.resolve()):
        raise ValueError("The fixture workspace must be outside the repository and separate from the output.")
    app = app or QCoreApplication.instance() or QCoreApplication([])
    order = [(spec, repeat) for spec in specs for repeat in range(repeats)]
    random.Random(order_seed).shuffle(order)
    experiment_id = f"eval-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    (output / "runs").mkdir(parents=True)
    manifest = {
        "format_version": FORMAT_VERSION, "experiment_id": experiment_id, "created_wall": time.time(),
        "environment": environment_info(),
        # The policy fixed for this experiment, whichever version was selected.
        "policy_version": policy_version, "policy_status": selected["status"], "policy_note": selected["note"],
        "frozen_policy": selected["policy"], "frozen_policy_sha256": policy_sha256(selected["policy"]),
        "label_rule": LABEL_RULE,
        "primary_criterion": "Run is positive if any scored assessment in its observation window reaches High "
                             f"(score >= {selected['policy']['high_threshold']}). Uncertain is reported separately.",
        "parameters": {"repeats": repeats, "order_seed": order_seed, "quiet_before_s": QUIET_BEFORE_S,
                       "settle_min_s": SETTLE_MIN_S, "settle_idle_s": SETTLE_IDLE_S, "settle_max_s": SETTLE_MAX_S,
                       "workspace": "system temporary directory" if workspace.parent == Path(tempfile.gettempdir())
                       else "custom", "response_mode": "alert_only"},
        "workloads": [spec.to_dict() for spec in specs],
        "run_order": [f"{spec.workload_id}#r{repeat}" for spec, repeat in order],
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    runs = []
    for index, (spec, repeat) in enumerate(order, start=1):
        run_id = f"{index:03d}-{spec.workload_id.replace('/', '-')}-r{repeat}"
        progress(f"[{index}/{len(order)}] {spec.workload_id} (label={spec.label}, repeat={repeat})")
        record = run_once(app, spec, repeat, workspace, keep_fixtures=keep_fixtures, run_id=run_id,
                          evidence_dir=(output / "evidence") if export_evidence else None,
                          policy_version=policy_version)
        record["experiment_id"] = experiment_id
        (output / "runs" / f"{run_id}.json").write_text(json.dumps(record, indent=2, allow_nan=False), encoding="utf-8")
        runs.append(record)
        progress(f"    -> {record['status']} max_level={record.get('max_level')} peak={record.get('peak_score')} "
                 f"latency={record.get('timings', {}).get('detection_latency_s')} error={record.get('error')}")
    summary = eval_metrics.summarize(runs)
    summary.update({"experiment_id": experiment_id, "policy_version": policy_version,
                    "frozen_policy_sha256": manifest["frozen_policy_sha256"],
                    "caveat": "Synthetic workloads on one host; not real-ransomware detection accuracy."})
    (output / "summary.json").write_text(json.dumps(summary, indent=2, allow_nan=False), encoding="utf-8")
    with (output / "runs.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for r in runs:
            timings = r.get("timings", {})
            writer.writerow({
                "run_id": r["run_id"], "workload_id": r["workload_id"], "label": r["label"], "split": r["split"],
                "repeat": r["repeat"], "seed": r["seed"], "status": r["status"],
                "max_level": eval_metrics.outcome_level(r.get("max_level")), "peak_score": r.get("peak_score"),
                "detection_latency_s": timings.get("detection_latency_s"),
                "delivery_delay_s": timings.get("delivery_delay_s"),
                "workload_duration_s": timings.get("workload_duration_s"),
                "exact_coverage": r.get("coverage", {}).get("exact_coverage", {}).get("display"),
                "late_observations": r.get("evidence", {}).get("late_observations"),
                "dropped_notifications": r.get("evidence", {}).get("dropped_notifications"),
                "error": r.get("error"), "policy_version": r.get("policy_version")})
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, help="New or empty directory for results")
    parser.add_argument("--split", choices=["development", "heldout", "all"], default="all")
    parser.add_argument("--workload", action="append", help="Workload id or base id (repeatable)")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--order-seed", type=int, default=20261118)
    parser.add_argument("--workspace", type=Path, help="Fixture parent directory (default: system temp)")
    parser.add_argument("--keep-fixtures", action="store_true")
    parser.add_argument("--export-evidence", action="store_true", help="Also export each run's SQLite evidence (ablation input)")
    parser.add_argument("--policy", choices=list(EVALUATION_POLICIES), default=DEFAULT_POLICY_VERSION,
                        help=f"Detection-rule policy to evaluate (default: {DEFAULT_POLICY_VERSION}, the M3 baseline)")
    parser.add_argument("--list", action="store_true", help="List policies, workloads and labels, then exit")
    parser.add_argument("--writer", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.writer is not None:
        return eval_workloads.writer_main(args.writer)
    specs = eval_workloads.select(eval_workloads.catalog(), args.split, args.workload)
    if args.list:
        for version, entry in EVALUATION_POLICIES.items():
            default = " (default)" if version == DEFAULT_POLICY_VERSION else ""
            print(f"policy {version:8s} {entry['status']:12s} sha256={policy_sha256(entry['policy'])[:12]}{default}")
        for spec in specs:
            print(f"{spec.workload_id:42s} {spec.label:10s} {spec.split:11s} {spec.description}")
        return 0
    if args.output is None:
        parser.error("--output is required")
    if not specs:
        parser.error("No workloads selected")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    summary = run_experiment(specs, args.output, repeats=args.repeats, order_seed=args.order_seed,
                             workspace=args.workspace, keep_fixtures=args.keep_fixtures,
                             export_evidence=args.export_evidence, policy_version=args.policy)
    overall = summary["overall"]
    print(json.dumps({"experiment_id": summary["experiment_id"], "policy_version": summary["policy_version"],
                      "completed_runs": summary["completed_runs"],
                      "failed_runs": len(summary["failed_runs"]), "confusion": overall["confusion"],
                      "metrics": {k: v["display"] for k, v in overall["metrics"].items()}}, indent=2))
    return 0 if not summary["failed_runs"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
