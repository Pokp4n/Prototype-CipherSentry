"""Process metadata collection does not establish who wrote a file.

Only call this for an independently known PID. Never enumerate processes and
guess a writer from a process name, file handle, or a coincident timestamp.
"""
from __future__ import annotations

import math
import time

import psutil


def collect_process_context(pid: int, expected_create_time: float | None = None) -> dict:
    """Read a stable process snapshot, reporting unavailable fields explicitly.

    Creation time is rechecked after collection to detect exit/PID reuse. Command
    line values are intentionally not retained: they can contain credentials.
    Metadata identity validation is not file-operation attribution and does not
    authorize containment. Authenticode signature verification is not implemented.
    """
    result = {
        "pid": pid, "name": None, "executable": None, "parent_pid": None,
        "create_time": None, "signature_status": "not_checked",
        "command_line_available": None, "identity_verified": False,
        "status": "unavailable", "missing": [], "errors": [],
        "collected_at": time.time(),
        "attribution_note": "Process metadata alone does not attribute file operations.",
    }
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        result["errors"].append("A positive integer PID is required.")
        return result
    if expected_create_time is not None and (
        isinstance(expected_create_time, bool)
        or not isinstance(expected_create_time, (int, float))
        or not math.isfinite(expected_create_time)
    ):
        result["errors"].append("Expected process creation time must be finite.")
        return result
    try:
        process = psutil.Process(pid)
        created = process.create_time()
        if expected_create_time is not None and created != expected_create_time:
            result["status"] = "identity_changed"
            result["errors"].append("PID no longer matches the expected process creation time.")
            return result
        result["create_time"] = created
        for key, getter in [
            ("name", process.name), ("executable", process.exe),
            ("parent_pid", process.ppid),
        ]:
            try:
                value = getter()
                result[key] = value if value != "" else None
                if result[key] is None:
                    result["missing"].append(key)
            except psutil.AccessDenied:
                result["missing"].append(key)
                result["errors"].append(f"Permission denied for {key}.")
        try:
            result["command_line_available"] = bool(process.cmdline())
        except psutil.AccessDenied:
            result["missing"].append("command_line")
        # Construct a fresh Process: Process.create_time() caches its result.
        current = psutil.Process(pid)
        if current.create_time() != created or not current.is_running() or current.status() == psutil.STATUS_ZOMBIE:
            result["status"] = "identity_changed"
            result["errors"].append("Process exited or changed identity during metadata collection.")
            return result
        result["identity_verified"] = True
        result["status"] = "partial" if result["missing"] else "available"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        result["errors"].append("Process is no longer available.")
    except psutil.AccessDenied:
        result["errors"].append("Permission denied while validating process identity.")
    result["missing"].append("digital_signature")
    return result
