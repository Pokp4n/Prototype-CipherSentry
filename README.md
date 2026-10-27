# CipherSentry

**An explainable behavioural ransomware detection and containment research prototype.**

A native Python + PySide6 desktop application based on the CipherSentry FYP proposal. It combines a live folder monitor, transparent behavioural scoring, local evidence history, and an isolated simulation lab with real pause/resume controls.

![CipherSentry dashboard](docs/screenshots/overview.png)

## Run on Windows

1. Install **64-bit Python 3.12** from [python.org](https://www.python.org/downloads/windows/), including the Python launcher.
2. Open Command Prompt in this project and run `setup_windows.bat`.
3. Run `run_windows.bat` to open the desktop application.

No administrator privileges are needed for the supported workflow. Initial installation downloads the pinned dependencies. The application itself uses local files and local child-process communication.

Equivalent commands:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m ciphersentry
```

The source application targets Windows. Development and automated checks also run on Linux; that does not extend the proposal's protection scope to Linux. This delivery was tested in a Linux cloud environment using Qt's offscreen platform. Interactive Windows operation and Windows performance still require validation on your own test machine. A packaged Windows executable has not been produced or verified.

## Try the prototype

1. Open **Simulation lab** and run **Rapid modification burst**. The app creates 60 disposable files under a fresh lab directory. The worker rewrites generated files with deterministic high-entropy bytes and renames them. It uses no malware or encryption.
2. Watch the five signal contributions and the risk score in **Overview**. At the default threshold of 75, corroborating evidence automatically pauses the registered simulation worker.
3. Inspect **Event explorer**, double-click an event for its explanation, and review the response audit. **Release worker** resumes the experiment and bypasses automatic containment for the rest of that run. **Stop experiment** terminates only that child.
4. Run **Ordinary bulk text edits**. This workload exercises frequent changes across directories without a large entropy increase. It stays below the default containment threshold.
5. Use **Choose folder → Start monitoring** for real filesystem observations. Edit a disposable text file in that folder, then inspect the recorded event and measured entropy. Monitoring is recursive, bounded, and advisory.
6. Use **Export evidence** to save JSON (events, explanations, and response actions) or CSV (events and explanation JSON). Adjust the high-risk threshold and automatic lab response in **Settings**.

The risk panel shows current evidence in a rolling ten-second window. A score decays as events expire; historical scores and decisions remain in the event log. The lab retains its peak score and observed changes at pause for review.

## What is implemented

| Proposal feature | Prototype behaviour |
| --- | --- |
| Real-time file monitoring | Watchdog notifications, bounded baseline, before/after sampled byte entropy, operation and directory observations |
| Multi-signal assessment | Five explicit point contributions: file activity, entropy rise, directory spread, repeated operations, and suspicious rename suffixes |
| Explainable decisions | Signal values, scoring explanations, risk levels, event details, and exported evidence |
| Adaptive containment | Real suspend/resume/terminate for a verified, directly launched lab child; high score and at least three contributing signal families required for automatic pause |
| Dashboard | Native Qt overview, risk chart, event explorer, simulation lab, settings, and sampled app CPU/memory |
| Experimental groundwork | Benign and suspicious synthetic scenarios, run records, unit/integration tests, and an evaluation protocol |

**Important attribution boundary:** ordinary filesystem notifications do not reliably identify the process that performed an operation. Folder events are explicitly labelled **Unattributed activity** and never trigger arbitrary process containment. The lab's PID is known because CipherSentry launches and verifies its worker. A Windows ETW/minifilter collector and robust event-to-process correlation are future work needed to meet the full endpoint containment objective.

These rules are an inspectable research baseline. They have not been trained or calibrated against a representative malware/benign dataset. Passing the included scenarios is functional validation, not an accuracy result. Legitimate compression/encryption can overlap with the chosen signals; low-and-slow attacks, dropped notifications, sample placement, and unknown attribution remain limitations. There is no file recovery, decryption, family identification, or network detection.

## Architecture

```text
Native PySide6 UI
       │ direct Python calls / queued Qt signals
       ▼
Controller ────── SQLite event + response audit ───── JSON / CSV
       │
       ├── FolderMonitor (watchdog + sampled entropy) ──┐
       │                                               ▼
       ├── QProcess lab worker ── JSON-lines ────── RiskEngine
       │                                               │
       └── ManagedContainment ◄── explained decision ───┘
             verified child PID + creation time + executable
```

The engine and persistence layer are independent of Qt. Folder monitoring runs off the UI thread, and Qt signals return events to the controller. The separate lab process allows genuine suspension without freezing the dashboard. Communication stays on local standard I/O pipes.

## Development and checks

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q
.venv/bin/python -m ciphersentry
```

On Windows, use `.venv\Scripts\python.exe -m pytest -q`. Controller tests select Qt's offscreen backend automatically before importing Qt.

For a headless UI capture:

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -m ciphersentry \
  --data-dir /tmp/ciphersentry-demo --demo suspicious \
  --screenshot /tmp/ciphersentry-overview.png
```

Use the existing checkout for cloud tasks; each task already has an isolated environment. A separate Git worktree is unnecessary.

## Local data

Windows data defaults to `%LOCALAPPDATA%\CipherSentry`; Linux development uses `$XDG_DATA_HOME/CipherSentry` or `~/.local/share/CipherSentry`. Override it with `--data-dir PATH`.

- `evidence.sqlite3`: persisted events, explanations, and response history.
- `settings.json`: local policy values.
- `lab/`: independently created disposable experiment folders, retained for inspection.
- `lab-results.jsonl`: completed/stopped run records and policy settings.

Close the application before archiving or removing the data directory. The app does not automatically delete evidence or fixtures. Disk retention is not yet automated. CPU and memory readings describe the dashboard process only, not a full system benchmark. File-change counts are worker observations; independent filesystem reconciliation belongs in the formal evaluation.

## Proposal and evaluation

- [Proposal analysis and implementation mapping](docs/PROPOSAL_ANALYSIS.md)
- [Evaluation plan and metric definitions](docs/EVALUATION_PLAN.md)
- [Validation results](docs/VALIDATION.md)

The proposal was used as project requirements and context. Its citations have not been independently verified in this implementation task.
