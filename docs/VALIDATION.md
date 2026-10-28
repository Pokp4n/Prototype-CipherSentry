# Validation record

This file distinguishes historical baseline evidence from the updated implementation. A functional simulation is not a malware detection benchmark. Current test commands and the Windows checklist are in [TESTING.md](TESTING.md).

## Historical baseline: commit `a29f70f`

The original Python 3.12.14 / PySide6 6.8.3 / watchdog 6.0.0 / psutil 7.0.0 prototype passed **33 tests** on the Linux cloud host. Qt was exercised with its offscreen platform. The original policy automatically paused a cooperative suspicious worker at score 76 after four fixture changes, while the original benign text workload peaked at 55. Those figures belong to the old five-signal policy, which included a separately scored rename suffix. They must not be reused as results for the updated policy.

That baseline verified real filesystem modifications, sampled entropy, local persistence, isolated lab fixtures, identity-restricted child control, and desktop interaction. It did not verify Windows operation or real ransomware detection accuracy.

## Updated implementation validation

The update changes the rules and response defaults. Validation must cover:

- Configurable five-indicator rules, Low/Uncertain/High, missing evidence, single-directory activity, and disabled-indicator comparisons.
- Alert-only defaults and safe migration of legacy settings; explicit simulation opt-in and separate response checks.
- Process metadata identity checks without treating context as writer attribution.
- Additive SQLite migration, response decisions, alert acknowledgement, and exports preserving historical evidence.
- Independent harmless-writer comparison with real folder observations, including unknown attribution and observation quality metrics.
- Actual Qt workflows, optional owned-worker pause/release, and cleanup on close.

The final local run completed with **86 tests passed in 32.73 seconds**, with no failures or skips. It used Python 3.12.14 and Qt's offscreen platform on Linux. The [JUnit result](validation/tests-linux.xml) records individual test outcomes.

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q \
  --junitxml=.ciphersentry/validation/tests-linux.xml
```

The tests exercise real file changes and owned worker suspension/resumption, not only mocked callbacks. The updated desktop journey confirms that a default alert-only suspicious run completes all 60 generated changes without automatic suspension; alerts can be acknowledged without controlling the worker. Explicit simulation opt-in still permits verified child containment. The legitimate ZIP scenario creates readable archives and preserves its original dummy files.

## Independent collector observation

The [raw Linux attribution report](validation/attribution-linux.json) records one 12-file harmless-writer experiment:

| Measurement | Observed result |
| --- | ---: |
| Expected / observed unique file modifications | 12 / 12 |
| Missing modifications / duplicate filtered notifications | 0 / 0 |
| Correctly attributed / unattributed notifications | 0 / 12 |
| Median callback delivery delay | 61.35 ms |
| Maximum observed callback delivery delay | 63.03 ms |

All collector PIDs remain unknown. These delays include the collector's 60 ms debounce; they are not ransomware detection latency. This single Linux run does not establish Windows results, raw kernel-event completeness, or sustained-load performance.

## Offline ablation example

A separate real cooperative suspicious lab run completed 60 changes in alert-only mode, with two alert transitions and no suspension. Its [exported evidence](validation/lab-evidence.json) is the input to the [six-policy replay report](validation/ablation-linux.json).

| Replay policy | Peak score | High-risk crossings |
| --- | ---: | ---: |
| Full development policy | 100 | 1 |
| Without frequency | 70 | 0 |
| Without entropy | 65 | 0 |
| Without repeated operations | 75 | 1 |
| Without directory spread | 90 | 1 |
| Without process context | 100 | 1 |

Weights were not rescaled. Context contributes zero under the current rules, so removing it changes no score. These numbers describe deterministic rule outputs on one synthetic trace, not accuracy or proof that more indicators improve detection. First-high offsets in the raw report are recorded-event offsets, not measured real-time latency.

Five screenshots under [screenshots/](screenshots/) were captured from the actual Qt application in alert-only mode. The Windows/Linux GitHub Actions workflow runs the test suite on pushes and pull requests; the Windows job result has not been independently verified here.

## CI portability corrections

The user subsequently supplied CI screenshots showing Ubuntu test-collection errors from missing `libEGL.so.1`, and a Windows run with **83 passed, 2 failed, 1 skipped**. The two Windows failures were a legacy SQLite test connection left open during temporary-directory cleanup, and an ablation-report Unicode mismatch caused by reading UTF-8 using the platform's default encoding.

The workflow now installs the Ubuntu Qt graphics dependencies and checks imports before testing. Tests explicitly close the legacy setup connection and use UTF-8 for JSON I/O. Existing migration and full-report equality checks remain enabled; detection rules and application behaviour were not changed to make the tests pass.

After correction, the local Linux suite passed **86 tests in 35.16 seconds**, with no failures or skips. The [correction-run JUnit report](validation/ci-fix-linux.xml) preserves the results. The 21 storage/ablation tests additionally passed with `-X warn_default_encoding -W error::EncodingWarning`, and Qt runtime imports succeeded. The Windows/default-code-page mismatch was reproduced by decoding the same UTF-8 report as cp1252 before the fix.

The corrected hosted Ubuntu and Windows workflow results still require confirmation after the push. These local checks do not establish a fresh Windows pass.

## Platform and measurement limits

The available development host is Linux, with offscreen Qt for automated desktop checks. Interactive Windows execution, ETW provider feasibility, Windows notification behaviour, and Windows process-control permissions remain unvalidated here. A Windows executable is not included.

Current folder notifications do not identify the writer. Cooperative lab instrumentation is not independent endpoint attribution. No formal accuracy, false-positive, ransomware-family coverage, guaranteed file protection, or system-overhead result is established by the included demos. Run the labelled repeated Windows workloads in [EVALUATION_PLAN.md](EVALUATION_PLAN.md) before making those research claims.
