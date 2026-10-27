"""PID-reuse-resistant control limited to this application's own lab children."""

from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import psutil


class ContainmentError(RuntimeError):
    """The requested lab process could not be safely controlled."""


@dataclass
class _Identity:
    created: float
    parent: int
    suspended: bool = False


class ManagedContainment:
    """Allowlist exact direct lab children; never accept a dashboard-reported PID.

    Registration requires a live direct child launched with
    ``python -m ciphersentry.lab_worker``, or this same frozen executable with
    ``--lab-worker``. Every operation rechecks its creation
    time and parent. Methods return True after success and raise ContainmentError
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
        return any(command[index:index + 2] == ["-m", "ciphersentry.lab_worker"] for index in range(1, len(command) - 1))

    def register(self, pid: int) -> bool:
        if pid <= 0 or pid == os.getpid():
            raise ContainmentError("Only a verified lab child process can be registered.")
        try:
            process = psutil.Process(pid)
            if process.ppid() != os.getpid() or not self._is_lab_command(process.cmdline(), process.exe()):
                raise ContainmentError("Process is not this application's direct CipherSentry lab worker.")
            created = process.create_time()
        except psutil.Error as error:
            raise ContainmentError(f"Could not register lab process: {type(error).__name__}.") from error
        with self._lock:
            existing = self._managed.get(pid)
            if existing is not None and existing.created == created:
                return True
            self._managed[pid] = _Identity(created, os.getpid())
        return True

    def _verify(self, pid: int) -> tuple[psutil.Process, _Identity]:
        identity = self._managed.get(pid)
        if identity is None:
            raise ContainmentError("This process is not registered for lab containment.")
        try:
            process = psutil.Process(pid)
            if process.create_time() != identity.created or process.ppid() != identity.parent:
                self._managed.pop(pid, None)
                raise ContainmentError("Process identity changed; containment was refused.")
            if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
                raise ContainmentError("The lab process has already exited.")
        except psutil.Error as error:
            raise ContainmentError(f"Lab process is unavailable: {type(error).__name__}.") from error
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
                    # Do not forget a still-live suspended process after an OS refusal.
                    try:
                        self._verify(pid)
                    except ContainmentError:
                        pass
                    else:
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
