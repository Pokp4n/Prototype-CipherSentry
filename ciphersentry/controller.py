"""Qt coordination boundary: worker threads emit data; the GUI owns state and SQLite."""
from __future__ import annotations

from collections import deque
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import threading
import time

import psutil
from PySide6.QtCore import QObject, QProcess, QTimer, Signal

from .containment import ManagedContainment
from .engine import Assessment, FileEvent, RiskConfig, RiskEngine
from .attribution import collect_process_context
from .monitor import FolderMonitor
from .response import evaluate_response
from .storage import EventStore
from .telemetry import WATCHDOG_CAPABILITIES


class Controller(QObject):
    changed = Signal()
    event_received = Signal(object, object)
    assessment_changed = Signal(object)
    lab_changed = Signal()
    message = Signal(str)
    error = Signal(str)
    _folder_event = Signal(object)
    _monitor_ready = Signal(object)
    _monitor_error = Signal(str)

    def __init__(self, data_dir: Path, parent=None, *, monitor_factory=None):
        super().__init__(parent)
        self.data_dir = data_dir.expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._settings_warning = ""
        self.settings = self._load_settings()
        self.engine = RiskEngine(config=RiskConfig.from_dict(self.settings["risk_config"]))
        self.store = EventStore(self.data_dir / "evidence.sqlite3")
        if self._settings_warning:
            self.store.record_action("settings_migration", self._settings_warning)
        self.current_response = {"action": "monitor", "allowed": False, "reason": "Waiting for evidence", "checks": {}}
        self.monitor_factory = monitor_factory or FolderMonitor
        self.monitor_capabilities = getattr(self.monitor_factory, "capabilities", WATCHDOG_CAPABILITIES).to_dict()
        self._alert_levels: dict[str, str] = {}
        self._responses: dict[str, dict] = {}
        self.containment = ManagedContainment()
        self.monitor: FolderMonitor | None = None
        self.monitor_starting = False
        self.folder: Path | None = None
        self.assessment: Assessment | None = None
        self.recent = deque(maxlen=400)
        self.observed_files: set[str] = set()
        self.total_events = self.store.counts().get("events", 0)
        self.session_events = 0
        self.lab = self._empty_lab()
        self.process: QProcess | None = None
        self.cpu_percent = 0.0
        self.memory_mb = 0.0
        self._self_process = psutil.Process()
        self._self_process.cpu_percent()
        self._stdout_buffer = b""
        self._closed = False
        self._closing = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._pending_monitor: FolderMonitor | None = None
        self._folder_event.connect(self._on_folder_event)
        self._monitor_ready.connect(self._on_monitor_ready)
        self._monitor_error.connect(self._on_monitor_warning)
        self.error.connect(self._record_error)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(1000)

    @staticmethod
    def _empty_lab() -> dict:
        return {"status": "Idle", "scenario": "", "completed": 0, "total": 60,
                "pid": None, "root": "", "started_at": None, "first_event_at": None,
                "first_high_at": None, "contained_at": None, "files_at_containment": None,
                "released": False, "elapsed": 0.0, "peak_score": 0, "error": "", "process_context": {}}

    @property
    def monitoring(self) -> bool:
        return self.monitor is not None and self.monitor.running

    @property
    def lab_active(self) -> bool:
        return self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning

    def _load_settings(self) -> dict:
        config = RiskConfig()
        mode = "alert_only"
        try:
            value = json.loads((self.data_dir / "settings.json").read_text(encoding="utf-8"))
            if isinstance(value, dict):
                if value.get("schema_version") == 2:
                    config = RiskConfig.from_dict(value.get("risk_config", {}))
                    if value.get("response_mode") == "simulation":
                        mode = "simulation"
                else:
                    self._settings_warning = "Legacy settings migrated to alert-only mode and updated development rules; simulation requires a new explicit opt-in."
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError) as exc:
            self._settings_warning = f"Settings could not be loaded; using alert-only defaults: {exc}"
            config = RiskConfig()
        return {"schema_version": 2, "threshold": config.high_threshold,
                "auto_contain": mode == "simulation", "response_mode": mode,
                "risk_config": config.to_dict()}

    def save_settings(self, threshold: int, auto_contain: bool, risk_config: dict | None = None) -> None:
        if type(auto_contain) is not bool:
            raise ValueError("Simulation opt-in must be a boolean.")
        values = dict(risk_config if risk_config is not None else self.settings["risk_config"])
        values["high_threshold"] = threshold
        config = RiskConfig.from_dict(values)
        settings = {"schema_version": 2, "threshold": config.high_threshold,
                    "auto_contain": bool(auto_contain), "response_mode": "simulation" if auto_contain else "alert_only",
                    "risk_config": config.to_dict()}
        target = self.data_dir / "settings.json"
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        temporary.replace(target)
        self.settings = settings
        self.engine.configure(config)
        self.assessment = None
        self._alert_levels.clear()
        self._responses.clear()
        self.current_response = {"action": "monitor", "allowed": False, "reason": "Policy changed; awaiting new evidence", "checks": {}}
        self.store.record_action("policy_updated", json.dumps(settings))
        self.message.emit("Response policy saved.")
        self.assessment_changed.emit(None)
        self.changed.emit()

    def _record_error(self, text: str) -> None:
        if not self._closed:
            self.store.record_action("error_or_unavailable_evidence", text)

    @property
    def monitor_health(self) -> dict:
        return {"running": self.monitoring,
                "baseline_count": self.monitor.baseline_count if self.monitor else 0,
                "dropped_events": self.monitor.dropped_events if self.monitor else 0}

    def acknowledge_alert(self, alert_id: int) -> None:
        if self.store.acknowledge_alert(alert_id):
            self.changed.emit()

    def choose_folder(self, path: str | Path) -> None:
        folder = Path(path).expanduser().resolve(strict=True)
        if not folder.is_dir():
            raise ValueError("Choose an existing folder.")
        if self.data_dir == folder or folder in self.data_dir.parents or self.data_dir in folder.parents:
            raise ValueError("Choose a narrower folder outside CipherSentry's evidence directory to avoid monitoring its own logs.")
        if self.monitoring or self.monitor_starting:
            raise ValueError("Stop monitoring before changing the folder.")
        self.folder = folder
        self.changed.emit()

    def start_monitor(self) -> None:
        if self.folder is None:
            self.error.emit("Choose a folder to monitor first.")
            return
        if self.monitoring or self.monitor_starting:
            return
        self.monitor_starting = True
        self.changed.emit()
        # Construct on the GUI thread so close() can cancel even during baseline.
        monitor = self.monitor_factory(self.folder, self._folder_event.emit, self._monitor_error.emit)
        self._pending_monitor = monitor

        def prepare() -> None:
            try:
                if self._closing.is_set():
                    return
                monitor.start()
                if self._closing.is_set():
                    monitor.stop()
                else:
                    self._monitor_ready.emit(monitor)
            except Exception as exc:
                monitor.stop()
                self._monitor_error.emit(f"Monitor could not start: {exc}")

        self._monitor_thread = threading.Thread(target=prepare, name="ciphersentry-baseline", daemon=True)
        self._monitor_thread.start()

    def _on_monitor_ready(self, monitor: FolderMonitor) -> None:
        self.monitor_starting = False
        self._pending_monitor = None
        if self._closed:
            monitor.stop()
            return
        self.monitor = monitor
        self.store.record_action("monitor_started", f"Folder {self.folder}; baseline {monitor.baseline_count} files")
        self.message.emit(f"Monitoring started. Baseline sampled for {monitor.baseline_count} files.")
        self.changed.emit()

    def _on_monitor_warning(self, text: str) -> None:
        if self._closed:
            return
        if text.startswith("Monitor could not start:"):
            self.monitor_starting = False
        self.error.emit(text)
        self.changed.emit()

    def stop_monitor(self) -> None:
        if self.monitor is not None:
            self.monitor.stop()
            self.monitor = None
            self.store.record_action("monitor_stopped", "Folder monitoring stopped by user")
        self.changed.emit()

    def _on_folder_event(self, event: FileEvent) -> None:
        if not self._closed:
            self._ingest(event)

    def _ingest(self, event: FileEvent) -> None:
        assessment = self.engine.ingest(event)
        if event.source == "lab":
            self.lab["peak_score"] = max(self.lab["peak_score"], assessment.score)
            if assessment.level == "High" and self.lab["first_high_at"] is None:
                self.lab["first_high_at"] = time.time()
        valid = False
        if assessment.eligible_for_containment and assessment.pid == self.lab["pid"] and self.lab_active:
            try:
                self.containment.validate(assessment.pid)
                valid = True
            except Exception as exc:
                self.error.emit(f"Containment identity check failed: {exc}")
        decision = evaluate_response(assessment, mode=self.settings["response_mode"],
                                     managed_identity_valid=valid, worker_released=self.lab["released"],
                                     worker_running=self.lab["status"] == "Running")
        response = decision.to_dict()
        response["outcome"] = "not_attempted"
        if decision.allowed and decision.action == "suspend_lab":
            succeeded = self.pause_lab(automatic=True)
            response["outcome"] = "suspended" if succeeded else "failed"
            response["reason"] += " Worker suspended." if succeeded else " Suspension failed; see action history."
        assessment = replace(assessment, response_reason=response["reason"])
        self.current_response = response
        self._responses[assessment.key] = response
        if len(self._responses) > self.engine.MAX_GROUPS:
            self._responses.pop(next(iter(self._responses)))
        self.store.record_event(event, assessment, response=response)
        previous = self._alert_levels.get(assessment.key)
        if assessment.level in {"Uncertain", "High"} and previous != assessment.level:
            self.store.record_alert(assessment, response)
            self.store.record_action("response_decision", json.dumps(response), assessment.pid)
        self._alert_levels[assessment.key] = assessment.level
        if len(self._alert_levels) > self.engine.MAX_GROUPS:
            self._alert_levels.pop(next(iter(self._alert_levels)))
        self.total_events += 1
        self.session_events += 1
        if len(self.observed_files) < 10000:
            self.observed_files.add(event.path)
        self.recent.appendleft((event, assessment))
        current = self.engine.latest()
        selected = max(current, key=lambda item: (item.score, item.last_seen), default=assessment)
        selected_response = self._responses.get(selected.key, response)
        self.assessment = replace(selected, response_reason=selected_response["reason"])
        self.current_response = selected_response
        self.event_received.emit(event, assessment)
        self.assessment_changed.emit(self.assessment)
        self.changed.emit()

    def start_lab(self, scenario: str) -> None:
        if scenario not in {"suspicious", "benign", "compression"}:
            raise ValueError("Unknown lab scenario.")
        if self.lab_active:
            self.error.emit("Stop or finish the current simulation before starting another.")
            return
        if self.lab["pid"] is not None:
            self.engine.forget_process(self.lab["pid"])
        self.lab = self._empty_lab()
        self.lab.update(status="Starting", scenario=scenario, started_at=time.time())
        self._stdout_buffer = b""
        process = QProcess(self)
        self.process = process
        process.setProgram(sys.executable)
        worker_args = ["--scenario", scenario, "--workspace", str(self.data_dir / "lab"),
                       "--files", "60", "--delay", "0.10"]
        if getattr(sys, "frozen", False):
            process.setArguments(["--lab-worker", *worker_args])
        else:
            process.setArguments(["-m", "ciphersentry.lab_worker", *worker_args])
            process.setWorkingDirectory(str(Path(__file__).resolve().parent.parent))
        process.started.connect(self._lab_started)
        process.readyReadStandardOutput.connect(self._read_lab)
        process.readyReadStandardError.connect(self._read_lab_error)
        process.errorOccurred.connect(self._lab_process_error)
        process.finished.connect(self._lab_finished)
        process.start()
        self.lab_changed.emit()
        self.changed.emit()

    def _lab_started(self) -> None:
        if self.process is None:
            return
        pid = int(self.process.processId())
        self.lab["pid"] = pid
        try:
            self.containment.register(pid)
            identity = self.containment.validate(pid)
            self.lab["process_context"] = collect_process_context(pid, expected_create_time=identity["create_time"])
            self.engine.forget_process(pid)
        except Exception as exc:
            self.lab["error"] = str(exc)
            self.process.kill()
            self.error.emit(f"Could not register the managed worker: {exc}")
            return
        self.lab["status"] = "Running"
        self.store.record_action("lab_started", f"Controlled {self.lab['scenario']} workload", pid)
        self.lab_changed.emit()

    def _read_lab(self) -> None:
        if self.process is None:
            return
        self._stdout_buffer += bytes(self.process.readAllStandardOutput())
        lines = self._stdout_buffer.split(b"\n")
        self._stdout_buffer = lines.pop()
        for line in lines:
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                kind = payload.get("type")
                if kind == "ready":
                    self.lab["root"] = payload["root"]
                    self.lab["total"] = payload["total"]
                elif kind == "event":
                    event = FileEvent(**payload["event"])
                    # The worker may only claim its registered identity.
                    if event.pid != self.lab["pid"] or event.source != "lab":
                        raise ValueError("Unexpected worker event identity")
                    event = replace(event, attribution="cooperative_lab",
                                    process_context=self.lab["process_context"], observed_at=time.time())
                    self.lab["completed"] = payload["completed"]
                    if self.lab["first_event_at"] is None:
                        self.lab["first_event_at"] = event.timestamp
                    self._ingest(event)
                    if self.lab["status"] == "Contained":
                        # Include any already-completed work buffered before suspension.
                        self.lab["files_at_containment"] = payload["completed"]
                elif kind == "complete":
                    self.lab["completed"] = payload["completed"]
                    self.lab["elapsed"] = payload["elapsed"]
                    self.lab["status"] = "Completed"
                elif kind == "error":
                    self.lab["error"] = str(payload.get("message", payload))
                    self.error.emit(self.lab["error"])
            except (ValueError, KeyError, TypeError) as exc:
                self.error.emit(f"Invalid worker response: {exc}")
        self.lab_changed.emit()

    def _read_lab_error(self) -> None:
        if self.process is not None:
            error = bytes(self.process.readAllStandardError()).decode("utf-8", "replace").strip()
            if error:
                self.lab["error"] = error[-2000:]
                self.error.emit(self.lab["error"])

    def _lab_process_error(self, error) -> None:
        if error == QProcess.ProcessError.FailedToStart:
            self.lab["status"] = "Failed"
            self.error.emit("The simulation process could not start.")
            self.lab_changed.emit()

    def _lab_finished(self, exit_code: int, exit_status) -> None:
        self._read_lab()
        if self.lab["pid"] is not None:
            self.containment.unregister(self.lab["pid"])
        if self.lab["status"] not in {"Completed", "Stopped"}:
            self.lab["status"] = "Failed" if exit_code != 0 else "Completed"
        if not self._closed:
            self.store.record_action("lab_finished", json.dumps(self.lab), self.lab["pid"])
            self._save_lab_result()
        self.lab_changed.emit()
        self.changed.emit()

    def _save_lab_result(self) -> None:
        results = self.data_dir / "lab-results.jsonl"
        result = {**self.lab, "policy": self.settings.copy(), "recorded_at": time.time(),
                  "environment": sys.platform, "note": "Controlled synthetic workload; not detection accuracy."}
        with results.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(result) + "\n")

    def pause_lab(self, automatic: bool = False) -> bool:
        if not self.lab_active or self.lab["status"] != "Running":
            return False
        try:
            if automatic and self.settings["response_mode"] != "simulation":
                return False
            self.containment.validate(self.lab["pid"])
            self.containment.suspend(self.lab["pid"])
            self.lab["status"] = "Contained"
            if self.lab["contained_at"] is None:
                self.lab["contained_at"] = time.time()
                self.lab["files_at_containment"] = self.lab["completed"]
            reason = "Multi-signal threshold reached" if automatic else "Manual pause by user"
            self.store.record_action("worker_suspended", reason, self.lab["pid"])
            self.message.emit(f"Simulation worker paused. {reason}.")
        except Exception as exc:
            self.error.emit(f"Containment failed: {exc}")
            return False
        self.lab_changed.emit()
        self.changed.emit()
        return True

    def resume_lab(self) -> None:
        if not self.lab_active or self.lab["status"] != "Contained":
            return
        try:
            self.containment.resume(self.lab["pid"])
            self.lab.update(status="Running", released=True)
            self.store.record_action("worker_resumed", "User released worker; auto-containment bypassed for this run", self.lab["pid"])
            self.message.emit("Worker released. Automatic containment is bypassed for the rest of this run.")
        except Exception as exc:
            self.error.emit(f"Could not resume worker: {exc}")
        self.lab_changed.emit()
        self.changed.emit()

    def stop_lab(self) -> None:
        if not self.lab_active:
            return
        try:
            self.lab["status"] = "Stopped"
            self.containment.terminate(self.lab["pid"])
            self.store.record_action("worker_stopped", "Managed simulation stopped by user", self.lab["pid"])
        except Exception as exc:
            self.error.emit(f"Could not stop worker: {exc}")
            # QProcess always refers to this exact child, never an unrelated PID.
            if self.process is not None:
                self.process.kill()
        self.lab_changed.emit()

    def export(self, path: Path) -> int:
        count = self.store.export_csv(path) if path.suffix.lower() == ".csv" else self.store.export_json(path)
        self.message.emit(f"Exported {count} evidence records to {path.name}.")
        return count

    def _tick(self) -> None:
        if self._closed:
            return
        self.cpu_percent = self._self_process.cpu_percent()
        self.memory_mb = self._self_process.memory_info().rss / (1024 * 1024)
        latest = self.engine.latest()
        live_keys = {item.key for item in latest}
        self._alert_levels = {key: level for key, level in self._alert_levels.items() if key in live_keys}
        self._responses = {key: value for key, value in self._responses.items() if key in live_keys}
        self.assessment = max(latest, key=lambda item: (item.score, item.last_seen), default=None)
        if self.assessment is not None:
            self.current_response = self._responses.get(self.assessment.key, {})
            self.assessment = replace(self.assessment, response_reason=self.current_response.get("reason", "No response decision recorded."))
        else:
            self.current_response = {"action": "monitor", "allowed": False, "reason": "No current evidence; historical alerts remain available.", "checks": {}}
        self.assessment_changed.emit(self.assessment)
        if self.lab_active and self.lab["started_at"] is not None:
            self.lab["elapsed"] = time.time() - self.lab["started_at"]
            self.lab_changed.emit()
        self.changed.emit()

    def close(self) -> None:
        if self._closed:
            return
        self._closing.set()
        self.timer.stop()
        if self._pending_monitor is not None:
            self._pending_monitor.stop()
        self.stop_monitor()
        self.stop_lab()
        if self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning:
            if not self.process.waitForFinished(2500):
                self.process.kill()
                self.process.waitForFinished(1500)
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=2)
        self._closed = True
        self.store.close()
