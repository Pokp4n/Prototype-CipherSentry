"""Verify an owned subprocess and the one supported Windows venv redirect.

Worker messages are claims, never authority. The launched PID, exact invocation,
OS executable, creation times and direct ancestry must independently agree.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import sys

import psutil


WINDOWS = os.name == "nt"


class ProcessIdentityError(RuntimeError):
    """An owned process cannot be independently verified."""


def _path(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProcessIdentityError("Process executable metadata is missing.")
    try:
        path = Path(value)
        if not path.is_absolute():
            raise ProcessIdentityError("Process executable must be an absolute path.")
        return os.path.normcase(str(path.resolve()))
    except (OSError, ValueError, RuntimeError) as error:
        raise ProcessIdentityError("Process executable path could not be verified.") from error


def _created(value: float) -> bool:
    return type(value) in {float, int} and math.isfinite(value) and value > 0


@dataclass(frozen=True)
class _Snapshot:
    pid: int
    create_time: float
    parent_pid: int
    executable: str
    command: tuple[str, ...]


def _snapshot(pid: int) -> tuple[psutil.Process, _Snapshot]:
    if type(pid) is not int or pid <= 4:
        raise ProcessIdentityError("Process PID is invalid or protected.")
    try:
        process = psutil.Process(pid)
        created = process.create_time()
        parent = process.ppid()
        executable = process.exe()
        command = tuple(process.cmdline())
        if (not _created(created) or type(parent) is not int or parent <= 0
                or not command or any(not isinstance(arg, str) for arg in command)):
            raise ProcessIdentityError("Required process identity metadata is unavailable.")
        if (not process.is_running() or process.status() in {psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD}
                or psutil.Process(pid).create_time() != created):
            raise ProcessIdentityError("Process exited or changed identity during validation.")
        _path(executable)
        _path(command[0])
        return process, _Snapshot(pid, created, parent, executable, command)
    except psutil.Error as error:
        raise ProcessIdentityError(f"Process identity is unavailable: {type(error).__name__}.") from error


def _matches(expected: _Snapshot) -> psutil.Process:
    process, current = _snapshot(expected.pid)
    if (current.create_time != expected.create_time or current.parent_pid != expected.parent_pid
            or _path(current.executable) != _path(expected.executable)
            or _path(current.command[0]) != _path(expected.command[0])
            or current.command[1:] != expected.command[1:]):
        raise ProcessIdentityError("Process identity, ancestry or invocation changed; action refused.")
    return process


@dataclass(frozen=True)
class OwnedProcessLaunch:
    """An OS-verified direct launch; only its expected interpreter may work."""

    _launcher: _Snapshot
    _owner_created: float
    _worker_executable: str

    @property
    def pid(self) -> int:
        return self._launcher.pid

    @property
    def arguments(self) -> tuple[str, ...]:
        return self._launcher.command[1:]

    @classmethod
    def capture(cls, pid: int, arguments: list[str]) -> OwnedProcessLaunch:
        if not isinstance(arguments, (list, tuple)) or any(not isinstance(arg, str) for arg in arguments):
            raise ProcessIdentityError("The expected invocation must contain exact string arguments.")
        if pid == os.getpid():
            raise ProcessIdentityError("The application itself cannot be registered as its worker.")
        try:
            owner = psutil.Process(os.getpid())
            owner_created = owner.create_time()
            if not _created(owner_created):
                raise ProcessIdentityError("Application creation time is unavailable.")
            _, launcher = _snapshot(pid)
            expected = _path(sys.executable)
            if (launcher.parent_pid != os.getpid() or launcher.create_time < owner_created
                    or _path(launcher.executable) != expected or _path(launcher.command[0]) != expected
                    or launcher.command[1:] != tuple(arguments)):
                raise ProcessIdentityError("Launched process is not the application's exact direct invocation.")
            worker_executable = launcher.executable
            if WINDOWS and not getattr(sys, "frozen", False):
                base = _path(getattr(sys, "_base_executable", sys.executable))
                if base != expected:
                    if base != _path(owner.exe()):
                        raise ProcessIdentityError("Windows base interpreter does not match the running application.")
                    worker_executable = str(Path(sys._base_executable).resolve())
            launch = cls(launcher, owner_created, worker_executable)
            launch._validate_launch()
            return launch
        except psutil.Error as error:
            raise ProcessIdentityError(f"Launch identity is unavailable: {type(error).__name__}.") from error

    def _validate_launch(self) -> None:
        try:
            if (self._launcher.parent_pid != os.getpid()
                    or psutil.Process(os.getpid()).create_time() != self._owner_created):
                raise ProcessIdentityError("The application's launch ownership changed.")
            _matches(self._launcher)
        except psutil.Error as error:
            raise ProcessIdentityError(f"Launch ancestry is unavailable: {type(error).__name__}.") from error

    def verify_worker(self, pid: int, expected_create_time: float) -> VerifiedWorker:
        if not _created(expected_create_time):
            raise ProcessIdentityError("Worker creation time is invalid or unavailable.")
        self._validate_launch()
        _, worker = _snapshot(pid)
        redirected = _path(self._worker_executable) != _path(self._launcher.executable)
        if redirected:
            if pid == self.pid or worker.parent_pid != self.pid or worker.create_time < self._launcher.create_time:
                raise ProcessIdentityError("Worker is not the verified Windows launcher's direct interpreter child.")
        elif pid != self.pid:
            raise ProcessIdentityError("Worker PID is not the captured direct launch.")
        if (worker.create_time != expected_create_time
                or _path(worker.executable) != _path(self._worker_executable)
                or _path(worker.command[0]) != _path(self._worker_executable)
                or worker.command[1:] != self.arguments):
            raise ProcessIdentityError("Worker identity does not match the independently verified invocation.")
        identity = VerifiedWorker(worker, self)
        identity.validate()
        return identity


@dataclass(frozen=True)
class VerifiedWorker:
    """Immutable worker identity; validate again immediately before OS control."""

    _worker: _Snapshot
    _launch: OwnedProcessLaunch

    @property
    def pid(self) -> int:
        return self._worker.pid

    @property
    def create_time(self) -> float:
        return self._worker.create_time

    @property
    def parent_pid(self) -> int:
        return self._worker.parent_pid

    @property
    def executable(self) -> str:
        return self._worker.executable

    @property
    def launch_pid(self) -> int:
        return self._launch.pid

    def validate(self) -> psutil.Process:
        self._launch._validate_launch()
        process = _matches(self._worker)
        # Recheck the anchor after reading the child to detect an ancestry race.
        self._launch._validate_launch()
        return process
