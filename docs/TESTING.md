# Testing and repeatable demonstration

These instructions distinguish automated functional checks, independent collector measurements, and the later formal Windows evaluation. Use disposable files and harmless programs. No real ransomware is needed for the supported workflow.

## 1. Install and run the tests

On Windows, install 64-bit Python 3.12 with the Python launcher, open Command Prompt in this repository, and run:

```bat
setup_windows.bat
.venv\Scripts\python.exe -m pip check
.venv\Scripts\python.exe -m pytest -q
run_windows.bat
```

On the Linux development host:

```bash
bash scripts/setup_cloud.sh
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q
```

The Qt integration tests use an offscreen platform. A pass there does not replace clicking through the app on Windows. Record the actual test count, failures, and skips from each run; do not reuse a historical count. Symlink creation can be unavailable to a standard Windows user, and the POSIX FIFO test is not applicable on Windows. A skipped test is not a passed test.

The suite covers configuration validation, missing evidence, sliding windows, single-directory detection, distinct-file versus repeated-write features, response safety, SQLite migration/exports, real filesystem observations, controlled worker actions, and desktop integration. See [VALIDATION.md](VALIDATION.md) for completed-run evidence.

## 2. Check alert-only behaviour first

Start with a new data directory so the policy is known:

```powershell
.venv\Scripts\python.exe -m ciphersentry --data-dir .ciphersentry\windows-demo
```

1. Confirm Settings shows alert-only and experimental rules.
2. Run the suspicious lab scenario. Confirm real generated files change and High-risk evidence can produce an alert while the worker continues.
3. Review the alert's evidence, unavailable information, and response reason. The wording should describe ransomware-like activity, not confirmed ransomware.
4. Acknowledge an alert. Confirm it remains in history with acknowledged status; no process action should follow acknowledgement.
5. Export JSON and inspect the events, responses, actions, and alerts. Close/reopen the application and confirm evidence persists.
6. Run the benign text-edit and ZIP-creation scenarios. For ZIP creation, verify that the generated archives can be opened and the original dummy text files remain intact. New archives have no before-entropy baseline. Record scores and alerts honestly; these controls do not establish a false-positive rate for other applications.

When an earlier settings file is loaded, confirm it migrates to alert-only rather than retaining an old automatic-pause setting. An invalid configuration should fail safely or be reported, not silently enable actions.

## 3. Test optional simulation response

Explicitly enable simulation response in Settings. Run a fresh suspicious workload and inspect why a pause is eligible. Verify that the displayed worker is the directly launched child and that file changes stop while it is suspended. Release it and confirm changes resume to completion. Release bypasses automatic suspension for that run. Also test Stop and closing the app while the owned worker is paused; no suspended child should remain.

Return to alert-only after the demonstration. Do not use this test as evidence that unrelated applications can be identified or contained. Essential-process exclusions, unknown identity, a reused PID, missing metadata, and unavailable permissions should result in refusal or a logged safe failure.

## 4. Test real folder observations

Create a disposable document folder outside CipherSentry's evidence directory. Add a text file, select the folder, wait for baseline completion, and modify the file. Check the observed operation, comparable entropy when available, and explicit unknown process identity. Test creates, renames, and deletes separately. Missing initial entropy is expected when a before-sample was not available.

Also try locked/inaccessible files and a larger burst. Preserve errors, baseline-limit warnings, and dropped-notification warnings. The current 5,000-file baseline and 64 KiB sample limit bound work but reduce coverage. Neither a modified notification nor the displayed event total is an exact count of all OS write calls.

## 5. Run the independent attribution probe

```powershell
.venv\Scripts\python.exe -m scripts.attribution_probe --files 12 --output .ciphersentry\attribution-windows.json
```

The harness creates a new owned fixture directory, starts the real folder collector, and launches a separate harmless writer. The writer's PID, creation time, and operations are ground truth; they are never copied into collector events. The report includes platform, capabilities, permissions, errors, observed/missing/duplicate modifications, stable identity comparisons, and delay samples. Fixture folders are retained for inspection. An optional `--workspace PATH` selects the parent for newly created run folders; existing files are not targets.

For the current watcher, expect collector PIDs to remain unknown because its API has no writer attribution. Report that result as a limitation rather than a failure to discover a nearby process. Inspect all metrics even when the command exits successfully: running the probe is not the same as observing every expected modification.

Coverage is defined per unique expected fixture modification, not per kernel write call. Duplicate counts are after collector filtering. Delivery delay includes debounce, queueing, sampling, and callback dispatch; notification timestamps use wall clock and may be affected by clock changes. Repeat on Windows at different loads and record each raw report. The same script on Linux tests only Linux's backend.

## 6. Compare indicator combinations

Export JSON evidence from a controlled run, then execute:

```powershell
.venv\Scripts\python.exe -m scripts.ablation evidence.json --output .ciphersentry\ablation.json
```

An optional `--config policy.json` supplies a frozen `RiskConfig` JSON object. The report compares the same observations under the baseline and individual indicator removals. Remaining weights are not rescaled. No replay can suspend or terminate a process. Score changes and first-high event offsets are not measured real-time detection latency or accuracy.

Exports containing different recorded policies require `--config` to select one explicit comparison policy. Example input and its resulting report are retained in [validation/](validation/). The tool limits each replay to 20,000 observations and 32 MiB of JSON.

Start by checking that removing an indicator affects only its configured contribution and that removing descriptive, zero-weight process context leaves the score unchanged. For the formal study, compare labelled workload outcomes and repeated runs, not just one synthetic trace. Calibration and evaluation sets must remain separate.

## 7. Windows readiness record

Record Windows edition/build, Python/dependency versions, repository commit, permissions, storage type, policy JSON, test output, probe reports, and any endpoint-security interference. Validate responsiveness, export/reopen, monitor stop/start, baseline warnings, paused-child cleanup, and app shutdown. Do not alter Defender or other tools silently to make a test pass.

ETW collection and Authenticode checks are not implemented here. Follow [WINDOWS_MONITORING_FEASIBILITY.md](WINDOWS_MONITORING_FEASIBILITY.md) before claiming process-level Windows detection. Use [EVALUATION_PLAN.md](EVALUATION_PLAN.md) for detection/false-positive metrics, independent file impact, and full monitoring-overhead measurements.

GitHub Actions runs the suite on `ubuntu-latest` and `windows-latest` with Python 3.12 and uploads JUnit results. Inspect the actual job outcomes and skips; local Linux passes do not imply that either remote job succeeded.

## CI troubleshooting

- **Ubuntu: `ImportError: libEGL.so.1`.** PySide6 needs operating-system graphics libraries even when Qt uses the offscreen platform. Pip installs the Python package but does not supply these system libraries. The workflow installs `libegl1`, `libgl1`, and `libopengl0` with apt before checking Qt imports and running tests. On a minimal Ubuntu development machine, install those packages with `sudo apt-get install libegl1 libgl1 libopengl0` after updating the package index.
- **Windows: `WinError 32` removing `legacy.sqlite3`.** The legacy migration test's setup connection was left open. A SQLite connection's normal context manager commits or rolls back transactions; it does not close the connection. The fixture now uses `contextlib.closing` as well as its transaction context, and checks that the connection is closed before testing migration.
- **Windows: a large ablation-report comparison mismatch.** Reports are UTF-8, while an unspecified text-file encoding can use Windows' default code page. The test now reads and writes JSON explicitly as UTF-8, preserving Unicode explanation text such as `Read → Write → Rename`. The full equality assertion is retained.

These fixes address runtime dependencies and test portability. They do not change behavioural rules, evidence, risk thresholds, or containment policy. A passing CI run establishes tested software behaviour; it does not establish ransomware detection accuracy or complete Windows telemetry coverage.
