# Windows process identity and Simulation Lab validation

Stage 5.2 investigation, 31 October 2026.

This report describes a focused repair to the existing Python/PySide6 prototype. The application architecture, indicator weights, risk thresholds, dependencies, and existing evidence database format are preserved.

## A. Verified root cause

The application confused the process that launched Python with the Python process that performed the workload. This was verified on the Windows laptop before implementation changes.

The diagnostic used `QProcess` to start the existing virtual environment's Python and read both the child's own report and independent operating-system metadata through `psutil`:

| Process | PID in this diagnostic | Parent PID | Executable reported by the operating system |
| --- | ---: | ---: | --- |
| Diagnostic parent | 29612 | 26092 | Base `Python312\python.exe` |
| Process returned by `QProcess.processId()` | 2788 | 29612 | Project `.venv\Scripts\python.exe` |
| Executing Python child | 34128 | 2788 | Base `Python312\python.exe` |

These are recorded example PIDs, not permanent identifiers or values used by the fix. The executing child still reported the virtual environment path in `sys.executable`. Therefore, reading `sys.executable` alone did not identify the actual operating-system executable or prove which PID executed the workload.

The observed relationship was:

```text
CipherSentry / diagnostic parent
  -> virtual environment Python launcher (QProcess PID)
       -> base Python interpreter (worker-reported PID)
```

The launcher and its child had the same arguments after the executable name. Their executable paths and process creation times were different.

The original controller registered the launcher PID as the worker. It ignored the PID in the worker's `ready` message and rejected each subsequent event because the event contained the executing child's PID. Consequently, 60 files could change while no events reached the risk engine or evidence store. Peak risk remained zero and detection latency was unavailable.

The original suspension test also suspended the launcher PID. The executing interpreter continued running and modifying fixtures. This was an identity error, not evidence that suspension of the correct interpreter had failed.

The attribution probe made a separate instance of the same assumption: it collected metadata for `Popen.pid`, then compared that PID with the writer's reported PID after the writer exited. It therefore compared the launcher's identity with the executing writer's identity. It also previously permitted unavailable independent metadata rather than requiring successful verification.

Additional integration defects were found:

- Rejected events only produced an error message. A later `complete` message or exit code zero could still mark the run Completed without accepted evidence.
- Killing a launcher alone did not reliably stop its executing child.
- A fixed startup sleep did not ensure that identity verification finished before workload modifications began.
- After the identity correction, a suspension check exposed a separate buffering issue: the fixture snapshot remained unchanged, but the displayed completed count moved from 6 to 7 when an event written before suspension arrived through the pipe. The controller now drains available events before publishing the final paused count. Buffered reporting is distinct from new file modifications.

The original Windows suite reproduced the reported result: **9 failed, 75 passed, 2 skipped in 62.03 seconds**. The three UI failures were downstream of rejected lab evidence; no separate UI implementation defect was established.

## B. Code changes

| File | Change and reason |
| --- | --- |
| [`ciphersentry/process_identity.py`](../ciphersentry/process_identity.py) | New shared verification boundary. Captures the independently launched process, its creation time, executable, exact arguments, and parent. Verifies either that direct worker or one specifically supported Windows virtual environment interpreter child. Rechecks identity before use. |
| [`ciphersentry/containment.py`](../ciphersentry/containment.py) | Registers the verified executing worker rather than the launcher. Pause, resume, and stop revalidate the worker and launch ancestry. Rejects wrappers as execution workers and unrelated commands that merely contain the lab module name later in their arguments. |
| [`ciphersentry/controller.py`](../ciphersentry/controller.py) | Keeps launch PID and worker PID separate. Verifies readiness before authorizing work, validates cooperative event identity and sequence, and requires completion to match accepted evidence. Failed validation remains Failed and retains an audit explanation. Handles buffered events around suspension. |
| [`ciphersentry/lab_worker.py`](../ciphersentry/lab_worker.py) | Managed runs report PID and creation time, wait for parent authorization before modifying generated fixtures, and remain alive for final evidence validation. Closing the parent pipe cancels cooperative work. |
| [`scripts/attribution_probe.py`](../scripts/attribution_probe.py) | Verifies the live writer through the shared launch/worker checks before authorizing modifications. Independently collects matching metadata and records the launch PID separately. Does not copy ground-truth identity into folder notifications. |
| [`tests/test_process_identity.py`](../tests/test_process_identity.py) | New regression coverage for the Windows redirect relationship, direct workers, unrelated claims, process exit, PID reuse, changed ancestry or invocation, missing metadata, and refusal of unsafe control. |
| [`tests/test_lab.py`](../tests/test_lab.py) | The real suspension test now verifies and controls the executing worker. It checks fixture stability during suspension and worker exit after stop. Adds refusal-before-authorization coverage. |
| [`tests/test_controller.py`](../tests/test_controller.py) | Strengthens risk and identity assertions and adds malformed identity/protocol, premature completion, and failed-run evidence preservation checks. |
| [`tests/test_attribution.py`](../tests/test_attribution.py) | Requires independently verified writer metadata and unchanged watchdog attribution. Rejection tests check that generated fixtures remain unmodified when verification fails. |
| [`README.md`](../README.md), [`TESTING.md`](TESTING.md), [`VALIDATION.md`](VALIDATION.md) | Clarify the executing-worker/launcher distinction and link this Windows record while preserving earlier research results. |
| [`windows-process-identity-tests.xml`](validation/windows-process-identity-tests.xml), [`windows-process-identity-smoke.json`](validation/windows-process-identity-smoke.json) | Retain the executed Windows suite results and measured scenario/probe evidence. The local repeatable harness is `artifacts/windows_process_validation.py`. |
| This report | Records the investigation and reproducible Windows verification procedure without replacing earlier research records. |

`engine.py`, `attribution.py`, and the response policy were inspected. No scoring-rule change was necessary. The existing process-context collector remains descriptive: it does not establish file-writer attribution or independently grant containment permission.

## C. Security verification

The verification sequence is:

1. Capture the PID obtained from the application's own `QProcess` or `Popen` launch. Verify that it is the application's direct child and that its executable and exact arguments match the requested invocation.
2. Treat the worker's reported PID and creation time as claims. Independently query the operating system while the worker is alive and idle.
3. Accept a direct worker only when it is the captured process. For the observed Windows virtual environment case, accept at most one direct interpreter child of the captured launcher. Its executable must match the configured base interpreter, which must also match the operating-system executable running the parent application. Its full remaining arguments must match the captured launch.
4. Validate creation times and ancestry for both launcher and worker. A fresh process object is used when checking for identity changes; cached creation-time values alone are insufficient.
5. Authorize the managed workload only after registration and independent metadata checks succeed. Fixture generation is confined to a newly created lab directory; workload modifications wait for this authorization.
6. Validate each cooperative lab message against the registered identity. Require the expected source, fixture location, sequence, and counts. Keep the worker alive until the controller acknowledges its validated completion.
7. Revalidate immediately before any pause, resume, or stop. If required identity information is unavailable or changed, reject the action and record the reason. Never search for an arbitrary replacement process or trust a reported PID alone.

Alert-only remains the default response mode. High risk records an assessment and alert without automatically suspending the worker. Automatic suspension still requires the user's explicit Simulation Lab opt-in and the existing response safety checks. Manual process controls also apply only to the verified lab worker.

Essential Windows process exclusions remain in place. A process name is not treated as proof of malware. Lab evidence remains labelled `cooperative_lab`; ordinary watchdog events retain unknown writer PIDs and unavailable attribution. The attribution probe's independently verified writer identity is ground truth for comparison only.

The changes do not add encryption, malware, discovery of personal documents, privilege changes, or security-product configuration changes. Existing fixture-ownership protections and exclusive file creation remain. Tests include pre-existing sample documents and assert that their contents remain unchanged. Existing SQLite evidence and research history are retained; no database reset is part of the fix.

## D. Testing results and limits

The final complete Windows run passed **155 tests, with 0 failures, 0 errors, and 2 skips in 52.17 seconds**. The [JUnit report](validation/windows-process-identity-tests.xml) contains all 157 collected cases. The skips are the POSIX-only named-pipe test and the symlink test because symlink creation is unavailable to this Windows account. Neither skip is counted as a pass.

Before the full run, the worker/controller/UI focused run passed **22 tests in 43.78 seconds**. The two additional fail-closed registration cases then passed **2 tests in 1.19 seconds**. An earlier focused run found the buffered-event issue described above; that run had 16 passes and one failure, and the issue was corrected without removing the stability assertion.

The final full-suite command was:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -ra --junitxml=docs/validation/windows-process-identity-tests.xml
```

The Windows host reported build **26200**, Python **3.12.10**, PySide6 **6.8.3**, watchdog **6.0.0**, psutil **7.0.0**, and pytest **8.3.5**. No upgrades were performed. The first restricted execution attempt was blocked by sandbox access to pytest temporary directories and process launches; the reported baseline and final results come from completed executions outside that restriction.

A separate real Qt-controller validation retained [measured results](validation/windows-process-identity-smoke.json):

| Scenario and policy | Accepted events | Peak risk | First High latency | Automatic suspensions |
| --- | ---: | ---: | ---: | ---: |
| Rapid modification burst, Alert-only | 60 | 100/100 | 0.608 s | 0 |
| Ordinary bulk text edits, Alert-only | 60 | 65/100 | No High assessment | 0 |
| Legitimate ZIP creation, Alert-only | 60 | 0/100 | No High assessment | 0 |
| Rapid modification burst, explicit simulation opt-in | 60 after release | 100/100 after release | 0.618 s | 1 |

The opted-in run paused after **7** accepted fixture changes. Its file names, modification times, and event count stayed unchanged during the 0.3-second observation, then it resumed to all 60 events. All four runs finished Completed with no controller errors. The benign text score of 65 is Uncertain under the unchanged rules; these results do not imply that all benign workloads score Low.

The independent Windows probe observed **12/12** expected unique modifications, with **0** missing and **0** duplicate filtered modifications in this run. All **12** notifications remained unattributed, giving **0%** writer-attribution coverage. The actual writer PID and creation time agreed with independently collected metadata, while its launcher PID was recorded separately. There were no collector errors. Callback delivery delay had a median of 0.6255 seconds and a maximum of 1.328 seconds; those notification-processing measurements are separate from lab detection latency.

The four SQLite databases, JSON exports, lab result files, and raw probe report are retained under `.ciphersentry/windows-identity-validation-7w62jbju/`. Existing normal application data was not used or reset. A pre-existing sentinel test document remained unchanged. The local harness can be repeated with `.\.venv\Scripts\python.exe -m artifacts.windows_process_validation`; each run creates a fresh data directory and replaces only the summary report with the new measurements.

The validation uses real Windows subprocesses, filesystem operations, Qt event loops, and `psutil` suspension for the integration tests. Unit tests additionally simulate unavailable metadata, altered ancestry, and PID reuse, which cannot be exercised safely or reliably by forcing arbitrary operating-system PID allocation.

The Qt/UI tests run offscreen. They exercise widget interactions and controller integration, but do not establish that a person has visually verified the interactive Windows desktop. The manual steps below remain necessary for that confirmation.

This work does not establish a current Linux runtime result or validate a packaged/frozen Windows executable. Direct and frozen identity rules have unit coverage; that is different from running an actual packaged application. Unknown wrapper types and deeper process trees are deliberately refused rather than assumed trustworthy.

If an already suspended worker loses its verifiable ancestry or the operating system denies essential metadata, safe control can be refused. The application must report that refusal rather than act on a possibly changed identity. This is a research prototype, not a guarantee of cleanup under every external process or permission change.

Successful lab operation demonstrates evidence collection, scoring, and authorized control of cooperative disposable workloads. It does not establish general Windows writer attribution, ransomware detection accuracy, a false-positive rate, or a zero-damage guarantee. Detection latency is the time from the first accepted lab event to the first High assessment under the configured experimental rules.

## E. Commands and manual verification

Use PowerShell in the existing project directory:

```powershell
Set-Location 'C:\dev\CipherSentry\Prototype-CipherSentry-main'
.\.venv\Scripts\python.exe -m pytest -q tests/test_process_identity.py tests/test_lab.py tests/test_attribution.py tests/test_controller.py tests/test_ui.py
.\.venv\Scripts\python.exe -m pytest -q
```

To include pytest skip explanations, use:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -rs
```

Launch the normal application with its existing evidence history:

```powershell
.\.venv\Scripts\python.exe -m ciphersentry
```

For a separate manual validation session, use a dedicated data directory instead:

```powershell
.\.venv\Scripts\python.exe -m ciphersentry --data-dir .ciphersentry\windows-manual-20261031
```

This optional path separates the manual experiment from the normal `%LOCALAPPDATA%\CipherSentry` data. If that validation directory already exists, its saved policy applies; check Settings explicitly before running.

Verify Rapid modification burst in Alert-only mode:

1. Open **Settings**, leave automatic simulation containment unchecked, and choose **Save rules and response policy**. Confirm that the application shows **Alert-only**.
2. Open **Simulation lab** and run **Rapid modification burst**.
3. Confirm that the experiment completes all 60 files, records a nonzero peak score that reaches High under the unchanged default rules, and displays a detection latency. It should not automatically pause.
4. Confirm that no `Unexpected worker event identity` error appears. Check **Event explorer** for this run's accepted events, consistent worker PID and creation time, and `cooperative_lab` attribution.
5. Check **Security alerts** and the response explanation. High risk should explain that automatic containment is disabled. Action history should contain no automatic worker suspension for this run.
6. Export JSON and inspect the run's response decisions. The per-run `lab-results.jsonl` should show Completed, 60 accepted events, the worker PID, and its separate launch PID. On the tested Windows virtual environment these two PIDs differ.

Verify the benign controls:

1. Run **Ordinary bulk text edits**. Confirm 60 accepted events, completion, and no automatic intervention.
2. Run **Run benign ZIP creation**. Confirm that ZIP events appear and that generated originals remain alongside valid ZIP archives. These controls should remain below High with the unchanged default settings; they do not represent every legitimate high-I/O application.

Verify explicitly authorized process control:

1. In **Settings**, explicitly enable simulation containment and save the policy.
2. Run a fresh **Rapid modification burst**. Confirm it pauses before all 60 fixtures are modified.
3. Observe that fixture names and modification times stop changing while paused. The paused count should settle after any already-written event data is drained.
4. Choose **Release worker**. Confirm that the worker resumes and completes, and that release bypasses another automatic pause for this run.
5. Start another run and choose **Stop experiment** while it is paused. Confirm the actual worker exits and the run is recorded as Stopped.
6. Restore Alert-only in Settings after the demonstration if that is the desired saved mode.

Run the independent attribution probe using only its generated fixtures:

```powershell
.\.venv\Scripts\python.exe -m scripts.attribution_probe --files 12 --workspace .ciphersentry\probe-fixtures --output .ciphersentry\attribution-windows.json
```

Check that the writer identity is consistent with independently collected metadata, while ordinary observations still have unknown PIDs and zero writer-attribution coverage. File-notification coverage and duplicate counts are measurements of that run and should be reported as observed.

Do not select personal document folders for these demonstrations. The Simulation Lab and probe create their own disposable fixture directories. No commit, push, dependency upgrade, or change to Windows Defender is required for these checks.
