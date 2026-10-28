# Feature status and gap assessment

Statuses describe the current implementation boundary, not research effectiveness. **Implemented** means code is present for the stated boundary; it does not mean Windows validation or representative accuracy evaluation is complete. Current test evidence is recorded separately in [VALIDATION.md](VALIDATION.md).

Allowed labels: **Implemented / Partially Implemented / Simulated / Research Pending / Not Started**.

## Existing foundation retained

The starting repository used Python, PySide6/Qt 6 with QSS, watchdog, psutil, SQLite, and pytest. Its working foundation included a native dashboard, real folder notifications, sampled entropy, deterministic rules, local exports, harmless generated lab fixtures, and identity-restricted child-process controls. The previous 33-test Linux suite is historical evidence for that baseline, not the test result for this update.

The application was extended rather than rebuilt. The major gaps were fixed numerical rules, the old rename-suffix fifth signal, no explicit alert lifecycle, limited missing-evidence reporting, default automatic lab pause, and no independent attribution comparison.

## Current versus required

| Feature | Status | Current boundary | Remaining work |
| --- | --- | --- | --- |
| Native Python/PySide6/QSS desktop | Implemented | Existing overview, events, lab, and settings retained; process evidence and security alerts added | Interactive Windows usability and responsiveness checks |
| Live folder observations | Partially Implemented | Real create/modify/move/delete notifications; bounded baseline and sampling; capability and coverage warnings | Windows workload validation; raw notification loss analysis; baseline race handling |
| Process attribution for ordinary applications | Research Pending | Folder records intentionally have unknown PID; no guessing from running processes | ETW provider feasibility, event correlation, and controlled Windows validation |
| Independent attribution test | Implemented | A harmless writer's ground truth is compared with independent watcher observations; unknown attribution is reported | Run on Windows and repeat under load; extend to each future collector |
| Known-process context | Partially Implemented | psutil metadata for an independently known PID, creation-time rechecks, explicit unavailable fields | Digital-signature verification and a justified contextual risk rule |
| Lab process identity | Simulated | Cooperative file telemetry plus a real verified child PID/creation time/executable | Does not replace independent endpoint attribution |
| Modification frequency | Implemented | Sliding-window modification rate and unique modified-path rate are distinct | Calibrate thresholds and assess notification coalescing |
| Entropy change | Partially Implemented | Before/after sampled byte entropy; missing evidence recorded | Segment strategies, partial changes, locked files, overhead evaluation |
| Repeated file operations | Partially Implemented | Counts and adjacent transitions, without one compulsory sequence; rename suffixes are descriptive support | Real reads and exact per-process writes require a stronger collector |
| Directory spread | Implemented | Distinct immediate modified-file parent directories; no requirement to span directories before High risk | Assess backup overlap and single-folder workloads |
| Process-context score | Research Pending | Context is shown but adds zero points regardless of configured weight | Propose, justify, implement, and evaluate contextual rules |
| Configurable Low/Uncertain/High assessment | Implemented | Configurable window, thresholds, weights, enabled indicators, values, reasons, and missing evidence | Freeze calibrated policy before held-out evaluation |
| Separate response safety decision | Implemented | Alert-only default; checks are independent of scoring and reasons are logged | Windows failure/permission testing |
| Arbitrary-application containment | Not Started | No automatic actions against arbitrary applications | Defer until attribution and safety gates pass |
| Controlled child pause/resume/stop | Simulated | Real OS actions restricted to the owned lab child; automatic pause requires explicit simulation mode | Verify Windows execution and measure independent response latency |
| Legitimate ZIP creation control | Implemented | Actual ZIP_DEFLATED archives of newly generated dummy files; originals retained | Add representative Windows archive applications and larger mixed workloads |
| Events, decisions, alerts, acknowledgements | Implemented | SQLite history, additive migration, JSON/CSV evidence, local audit trail | Retention, large-run performance, archival policy |
| Offline ablation tool | Implemented | Replay exported events with one indicator removed and unchanged remaining weights | Labelled Windows workload study and statistical analysis |
| Formal detection/false-positive evaluation | Research Pending | Protocol and fixture tools supplied | Run benign high-I/O/compression/encryption comparisons and held-out scenarios |
| Windows installer or packaged executable | Not Started | Python source launch scripts provided | Validate source workflow first, then investigate packaging if time permits |
| Kernel minifilter driver | Not Started | Advanced alternative documented only | Postpone unless an evidence-based feasibility review requires it |

## Important interpretation rules

A Low score is not proof of safety. A High score indicates high-risk ransomware-like file activity under development rules, not confirmed ransomware. Missing entropy, unknown PID, or unavailable metadata is recorded as uncertainty. A familiar process name or signature is not treated as automatic trust.

The system can display file activity without claiming to know the writer. The lab's cooperative instrumentation is labelled separately from live folder observations. Linux functional tests are distinct from Windows monitoring results. Neither source establishes accuracy across real ransomware families.
