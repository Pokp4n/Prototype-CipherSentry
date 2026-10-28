"""Separate response policy from behavioural assessment and OS process control.

This policy never suspends a process itself. A caller must revalidate the exact
registered child immediately before passing the decision to ManagedContainment.
``allowed`` means permission to attempt a lab suspension, not proof it succeeded.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from pathlib import PureWindowsPath

from .engine import Assessment


# A defence-in-depth exclusion, not a way to infer whether an application is safe.
# The managed-child allowlist remains mandatory even for every other process name.
ESSENTIAL_WINDOWS_PROCESSES = frozenset({
    "system", "registry", "secure system", "idle", "system idle process",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe",
})


@dataclass(frozen=True)
class ResponseDecision:
    action: str
    allowed: bool
    reason: str
    checks: dict

    def to_dict(self) -> dict:
        return asdict(self)


def evaluate_response(
    assessment: Assessment,
    mode: str = "alert_only",
    managed_identity_valid: bool = False,
    worker_released: bool = False,
    worker_running: bool = False,
) -> ResponseDecision:
    """Decide a safe next step without touching the operating system.

    Ordinary folder events cannot authorize containment. Even a future external
    collector's reliable attribution cannot enter this prototype's managed-child
    response path. Only the explicit ``simulation`` mode supports automatic pause.
    Names, signatures, and familiar executable paths never grant permission.
    """
    features = getattr(assessment, "features", {})
    context = features.get("process_context", {}) if isinstance(features, dict) else {}
    if not isinstance(context, dict):
        context = {}
    pid = assessment.pid
    created = context.get("create_time")
    executable = context.get("executable")
    stable_context = (
        type(pid) is int and pid > 4 and type(context.get("pid")) is int
        and context["pid"] == pid
        and type(created) in {int, float} and math.isfinite(created) and created > 0
        and isinstance(executable, str) and bool(executable.strip())
    )
    names = {str(context.get("name", "")).casefold(), str(assessment.process_name).casefold()}
    if isinstance(executable, str):
        names.add(PureWindowsPath(executable).name.casefold())
    checks = {
        "simulation_mode": mode == "simulation",
        "high_risk": assessment.level == "High",
        "corroborating_evidence": assessment.eligible_for_containment is True,
        "cooperative_lab_attribution": getattr(assessment, "attribution", "unavailable") == "cooperative_lab",
        "stable_process_context": stable_context,
        "essential_process_excluded": not bool(names & ESSENTIAL_WINDOWS_PROCESSES) and type(pid) is int and pid > 4,
        "managed_identity_revalidated": managed_identity_valid is True,
        "worker_running": worker_running is True,
        "worker_not_released": worker_released is False,
    }
    if assessment.level == "Low":
        return ResponseDecision("monitor", False, "Continue monitoring; the current evidence is below the uncertainty threshold. Missing evidence is not proof of safety.", checks)
    if assessment.level in {"Uncertain", "Elevated"}:
        return ResponseDecision("gather_evidence", False, "Gather more evidence and reassess. The current assessment does not justify process suspension.", checks)
    if assessment.level != "High":
        return ResponseDecision("alert_only", False, "Unsupported risk classification; no process action is permitted.", checks)

    if mode != "simulation":
        reason = "Alert-only policy: high-risk ransomware-like file activity was observed; automatic containment is disabled."
        if mode != "alert_only":
            reason = "Unknown response mode; falling back to alert-only with automatic containment disabled."
        return ResponseDecision("alert_only", False, reason, checks)

    failures = [
        ("cooperative_lab_attribution", "the source is not a cooperative managed-lab worker; ordinary or external process attribution cannot authorize this prototype's response"),
        ("stable_process_context", "stable process identity or executable metadata is missing or inconsistent"),
        ("essential_process_excluded", "the process matches an essential-system exclusion"),
        ("corroborating_evidence", "the separate multi-signal candidate condition was not met"),
        ("managed_identity_revalidated", "the registered child identity could not be revalidated"),
        ("worker_running", "the managed worker is not running"),
        ("worker_not_released", "the user released this worker for the remainder of the run"),
    ]
    blocked = [reason for name, reason in failures if not checks[name]]
    if blocked:
        return ResponseDecision("alert_only", False, "Containment was not attempted: " + "; ".join(blocked) + ".", checks)
    return ResponseDecision(
        "suspend_lab", True,
        "Simulation policy permits temporary suspension of this verified lab child: high risk, corroborating evidence, stable identity, and managed-worker safety checks passed. OS control must still revalidate identity and may fail.",
        checks,
    )
