"""PID-reuse-resistant control limited to this application's own lab children."""

from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import psutil

from .process_identity import OwnedProcessLaunch, ProcessIdentityError, VerifiedWorker


class ContainmentError(RuntimeError):
    """The requested lab process could not be safely controlled."""


@dataclass
class _Identity:
    worker: VerifiedWorker
    suspended: bool = False


class ManagedContainment:
    """Allowlist verified lab workers, including a Windows venv interpreter child.

    Registration requires an independently captured launch with
    ``python -m ciphersentry.lab_worker``, or this same frozen executable with
    ``--lab-worker``. Every operation rechecks the worker and launcher creation
    times, executables, arguments and ancestry. Methods return True after success and raise ContainmentError
    for invalid identity or operating-system refusal. ``terminate`` resumes first
    and escalates to kill after a bounded grace period without reaping QProcess.
    """

    def __init__(self) -> None:
        self._managed: dict[int, _Identity] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _is_lab_command(command: list[str], executable: str) -> bool:
        if not command:
            return False
        try:
            expected = Path(sys.executable).resolve()
            if Path(executable).resolve() != expected or Path(command[0]).resolve() != expected:
                return False
        except (OSError, RuntimeError):
            return False
        if getattr(sys, "frozen", False):
            return len(command) > 1 and command[1] == "--lab-worker"
        return command[1:3] == ["-m", "ciphersentry.lab_worker"]

    def register(self, pid: int, *, launch: OwnedProcessLaunch | None = None,
                 expected_create_time: float | None = None) -> bool:
        if type(pid) is not int or pid <= 4 or pid == os.getpid():
            raise ContainmentError("Only a verified lab child process can be registered.")
        try:
            if launch is None:
                process = psutil.Process(pid)
                command = process.cmdline()
                if process.ppid() != os.getpid() or not self._is_lab_command(command, process.exe()):
                    raise ContainmentError("Process is not this application's direct CipherSentry lab worker.")
                created = process.create_time()
                launch = OwnedProcessLaunch.capture(pid, command[1:])
                if expected_create_time is None:
                    expected_create_time = created
            if not isinstance(launch, OwnedProcessLaunch):
                raise ContainmentError("A captured process launch is required.")
            prefix = ("--lab-worker",) if getattr(sys, "frozen", False) else ("-m", "ciphersentry.lab_worker")
            if launch.arguments[:len(prefix)] != prefix:
                raise ContainmentError("Captured invocation is not a CipherSentry lab worker.")
            worker = launch.verify_worker(pid, expected_create_time)
        except (psutil.Error, ProcessIdentityError) as error:
            raise ContainmentError(f"Could not register lab process: {error}") from error
        with self._lock:
            existing = self._managed.get(pid)
            if existing is not None and existing.worker == worker:
                return True
            self._managed[pid] = _Identity(worker)
        return True

    def _verify(self, pid: int) -> tuple[psutil.Process, _Identity]:
        identity = self._managed.get(pid)
        if identity is None:
            raise ContainmentError("This process is not registered for lab containment.")
        try:
            process = identity.worker.validate()
        except ProcessIdentityError as error:
            raise ContainmentError(f"Lab process could not be revalidated: {error}") from error
        return process, identity

    def suspend(self, pid: int) -> bool:
        with self._lock:
            process, identity = self._verify(pid)
            if not identity.suspended:
                try:
                    process.suspend()
                except psutil.Error as error:
                    raise ContainmentError(f"Could not suspend lab process: {type(error).__name__}.") from error
                identity.suspended = True
        return True

    def validate(self, pid: int) -> dict:
        """Recheck the registered worker and launch without controlling either."""
        with self._lock:
            _, identity = self._verify(pid)
            worker = identity.worker
            return {"pid": pid, "create_time": worker.create_time, "parent_pid": worker.parent_pid,
                    "executable": worker.executable, "launch_pid": worker.launch_pid}

    def resume(self, pid: int) -> bool:
        with self._lock:
            process, identity = self._verify(pid)
            if identity.suspended:
                try:
                    process.resume()
                except psutil.Error as error:
                    raise ContainmentError(f"Could not resume lab process: {type(error).__name__}.") from error
                identity.suspended = False
        return True

    def is_suspended(self, pid: int) -> bool:
        with self._lock:
            _, identity = self._verify(pid)
            return identity.suspended

    def unregister(self, pid: int) -> bool:
        """Remove an exited child, or resume a live suspended child before removal."""
        with self._lock:
            identity = self._managed.get(pid)
            if identity is None:
                return False
            if identity.suspended:
                try:
                    self.resume(pid)
                except ContainmentError:
                    # Unavailable ancestry is not proof that a suspended worker exited.
                    try:
                        process = psutil.Process(pid)
                        same_live_process = (process.create_time() == identity.worker.create_time
                                             and process.is_running() and process.status() != psutil.STATUS_ZOMBIE)
                    except (psutil.NoSuchProcess, psutil.ZombieProcess):
                        pass
                    except psutil.Error as error:
                        raise ContainmentError(f"Cannot safely forget suspended worker: {error}") from error
                    else:
                        if same_live_process:
                            raise
            self._managed.pop(pid, None)
        return True

    def terminate(self, pid: int) -> bool:
        with self._lock:
            process, identity = self._verify(pid)
            try:
                if identity.suspended:
                    process.resume()
                    identity.suspended = False
                    process, _ = self._verify(pid)
                process.terminate()
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
                        self._managed.pop(pid, None)
                        return True
                    time.sleep(0.025)
                # Verify identity again before escalation; never signal a reused PID.
                process, _ = self._verify(pid)
                process.kill()
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
            except psutil.Error as error:
                raise ContainmentError(f"Could not stop lab process: {type(error).__name__}.") from error
            self._managed.pop(pid, None)
        return True
