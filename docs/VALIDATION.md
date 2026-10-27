# Prototype validation

This is a functional validation record for the delivered prototype, not a ransomware detection benchmark.

## Environment

- Linux cloud execution environment, Python 3.12.14.
- PySide6 6.8.3, watchdog 6.0.0, psutil 7.0.0.
- Qt offscreen platform for native widget rendering and interaction tests.
- No live malware or existing user documents used as simulation targets.

## Completed checks

`QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q`

**33 tests passed in 15.88 seconds; no failures or skips in this run.**

| Area | Evidence exercised |
| --- | --- |
| Scoring | Entropy calculation, multi-signal thresholds, benign high-I/O controls, missing baselines, rolling expiry, out-of-order evidence, bounded history, Windows paths, PID evidence reset |
| Persistence | SQLite event/action history, reopen persistence, explanations, JSON and CSV exports |
| Filesystem | Actual watchdog file modifications, measured entropy change, unknown PID, baseline limits, symlink/FIFO exclusion, cancellation during baseline |
| Lab isolation | Fresh disposable fixture directories, existing files preserved, benign and suspicious transformations |
| Process control | Refusal of unrelated processes, verified child suspension, stable files while paused, resume, termination, executable identity checks |
| Controller | Actual QProcess worker, automatic suspension, release to completion, benign completion, cross-thread file notifications, evidence persistence, cleanup on close |
| Desktop journey | Clicking lab navigation and Run, actual auto-containment, evidence filter, explanation data, JSON export, policy save, child cleanup |

Dependency consistency: `python -m pip check` reports **No broken requirements found**.

## Observed controlled behaviour

- At the default threshold of 75, the suspicious worker's first four fixture changes contribute **76 points** across all five signal families. The parent suspends its registered child and records the decision.
- During the pause, an independent test snapshot of fixture modification times remains stable. Releasing the worker completes all 60 changes.
- The benign text-edit worker completes all 60 files without automatic intervention and peaks at **55 points**.
- A real selected-folder modification records a measured entropy increase while retaining an unknown PID and no containment eligibility.
- Four real application screenshots are included under [screenshots/](screenshots/). They show live synthetic lab state, rather than fabricated security events.

The four-file trigger is a consequence of the current illustrative rule weights and synthetic workload. It is not a general claim about ransomware detection speed, damage prevented, or accuracy. CPU/memory in screenshots are samples of the dashboard process only.

## Outstanding validation

The Windows launch scripts and Windows-specific process/filesystem behaviour need execution on a Windows test machine. No Windows `.exe` is included. Source dispatch supports a future frozen executable, but executable packaging and its child I/O have not been validated.

Full endpoint process attribution remains future work. Formal accuracy, false-positive intervention, latency distributions, independent file impact, and system overhead results require the workloads and controls in [EVALUATION_PLAN.md](EVALUATION_PLAN.md).
