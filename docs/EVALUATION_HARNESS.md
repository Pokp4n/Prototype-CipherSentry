# Labelled evaluation harness

This harness implements the workload-run protocol in [EVALUATION_PLAN.md](EVALUATION_PLAN.md) for CipherSentry's **folder-monitoring detection path**. It measures how the existing, frozen rules respond to labelled synthetic workloads. **It does not measure real-ransomware detection accuracy**, and it does not measure containment.

| Component | Role |
| --- | --- |
| `scripts/eval_workloads.py` | Workload catalog, labels, deterministic fixtures and plans, confined plan execution, the writer subprocess |
| `scripts/eval_metrics.py` | Run classification, confusion counts, rates with explicit denominators, latency, coverage and indicator summaries |
| `scripts/evaluate.py` | Harness CLI: drives the real pipeline per run and writes machine-readable results |
| `tests/test_evaluation.py` | Determinism, label rule, confinement, metric edge cases and two real end-to-end runs |

## What one run does

1. Creates a fresh directory `cs-eval-*` under the fixture workspace (default: the system temporary folder, `%TEMP%\ciphersentry-eval`), writes an ownership marker, and generates the workload's fixtures from its seed.
2. Starts a **fresh CipherSentry `Controller`** with its own data folder: the same `FolderMonitor`, frozen `RiskEngine`, alert de-duplication, unscored late-observation handling and SQLite evidence store as the desktop app. There is no GUI. The response mode is verified as alert-only, and the live risk policy must equal `FROZEN_POLICY` exactly; otherwise the run fails.
3. Waits until the monitoring baseline is complete, then observes a 1 s quiet period. Any events in that period are recorded as `pre_workload_events` (contamination).
4. Launches a separate, harmless **writer process** (`python -m scripts.evaluate --writer <run>`). It refuses to run without the ownership marker, reports its clock in a handshake, waits for an explicit `start`, executes the plan, and prints one ground-truth record per file action. Closing its stdin cancels it.
5. After the writer finishes, keeps observing for at least 2 s and until the monitor backlog is empty and no event has arrived for 1.5 s (capped at 20 s).
6. Records the run, checks the safety invariants, stops monitoring, and deletes the fixtures. **A failed run keeps its fixtures** and records the error and traceback; failures are listed in the summary, never discarded.

The harness never starts the lab worker, never requests a process action, and never starts or runs an ETW collector. Each run's safety block checks this from the evidence store: no `lab_started`/`worker_*`/ETW audit actions, no response with an attempted or allowed action, no ETW candidate records, an unchanged policy and alert-only mode. A run that fails any check is marked failed.

## Workloads and independent labels

Labels are fixed by each workload's **design** before any run:

> A workload is **suspicious** when its design performs an unauthorized, ransomware-like impact: it replaces the original contents of at least three pre-existing fixture files with unrelated high-entropy bytes (in place, partially, or by writing a replacement and deleting the original) without keeping a recoverable copy. Every other workload is **benign**: it edits, copies, archives, appends or exports while preserving the user's data, or it is a transformation the user explicitly authorized.

`tests/test_evaluation.py` checks every plan against this rule structurally, without involving the engine.

| ID | Label | Behaviour | Why it is included |
| --- | --- | --- | --- |
| B01 | benign | A few documents edited twice in one or two folders | Everyday activity |
| B02 | benign | One document autosaved 20–30 times | Repeated operations on one file |
| B03 | benign | 40–60 documents rewritten with new low-entropy text across 4–5 folders | High rate and spread without entropy rise |
| B04 | benign | Copy of 40–50 documents into a mirrored backup tree | Backup-like creation activity |
| B05 | benign | ZIP archive created beside each of 30–40 documents | New high-entropy files, no prior baseline |
| B06 | benign | 30–40 new encrypted-looking export files in one folder | Legitimate high-entropy output |
| B07 | benign | 60–80 rapid appends to 3–4 log files | High notification rate on few files |
| B08 | benign | 30–40 existing high-entropy images re-rendered | Overwrites where entropy is already high |
| B09 | benign | User-authorized in-place encryption of 30–40 documents | **Intent-only difference** from S01; measures the limit of behaviour-only detection |
| S01 | suspicious | 40–50 documents overwritten with pseudorandom bytes across 4–5 folders | Classic rapid transformation |
| S02 | suspicious | Overwrite then rename to `.locked` / `.encrypted` | Rename suffixes (descriptive only in the engine) |
| S03 | suspicious | Overwrites in a single folder | No directory spread |
| S04 | suspicious | One overwrite every 1.6–2 s | Low-and-slow; below the lowest frequency band |
| S05 | suspicious | Only five files overwritten | Low volume |
| S06 | suspicious | Pseudorandom replacement created, original deleted | Create/delete pattern; not counted as modification |
| S07 | suspicious | First 4 KiB of larger documents overwritten | Partial change; sampled entropy may stay below 7 bits/byte |

Each workload has a **development** variant and a **held-out** variant with a different seed and different file counts, folder counts and rates. "Pseudorandom bytes" are seeded `random.Random` output: high entropy and reproducible, but not encryption. No key, cipher, discovery or persistence is involved.

Run `python -m scripts.evaluate --list` for the full catalog.

### Calibration and held-out discipline

No detection parameter was changed in Milestone 3. The evaluated policy is frozen in `FROZEN_POLICY` (window 10 s; thresholds 40/75; weights 30/35/25/10/0), its SHA-256 is written to every manifest, and the harness refuses to run if the engine's live configuration differs. Development variants were used only to build and debug the harness. If the rules are ever tuned, use only development runs for tuning, record the new policy, and then evaluate on a **new** held-out set; results on the current held-out set would then be exploratory.

## Time points and clock method

All latencies use `time.perf_counter`. On Windows this is QueryPerformanceCounter, which is consistent across processes. In the handshake the writer reports its `perf_counter` value. The parent's receive time minus that value must lie between −2 ms and +2 s. A negative value would mean the clocks are not shared; more than 2 s would mean a stalled pipe. This is a plausibility check on the shared clock, not a proof of it. If alignment fails, cross-process latencies are recorded as `null` rather than reported.

Detection latency is therefore measured from the writer's first file action to the moment the Controller emits the first High assessment, after the event has been scored and stored. It is not the callback or delivery delay; that is reported separately as `delivery_delay_s`.

| Field | Definition |
| --- | --- |
| `t_start` | Writer's `perf_counter` immediately before the first workload file action (fixture generation excluded) |
| `delivery_delay_s` | First event delivered to the Controller minus `t_start`. Includes OS notification, debounce, sampling and Qt delivery |
| `notification_delay_wall_s` | Collector notification time (`observed_at`, wall clock) minus the first action's wall-clock start. Wall clock; can be affected by clock adjustments |
| `first_uncertain_or_high_latency_s` | First assessment at Uncertain or High minus `t_start` |
| `detection_latency_s` | First **High** assessment minus `t_start`. `null` when not detected: never zero |
| `detected_after_workload_end` | Whether the first High came after the writer's last action |
| `observation_window_s` | End of the observation window minus `t_start` |

Observation delay and detection latency are reported separately.

## Metrics

The unit is the **workload run**. Thousands of notifications from one run are one sample.

- **Primary positive criterion (predeclared):** at least one scored assessment in the run's observation window reaches **High** (score ≥ 75).
- **Outcome levels:** every run is tabulated as High, Uncertain, Low or "No scored evidence" by label. Uncertain is never folded into a detection. An "Uncertain or High" confusion matrix is also reported, labelled as a sensitivity analysis only.
- **Counts:** TP = suspicious and positive; FN = suspicious and not positive; FP = benign and positive; TN = benign and not positive.
- **Rates** (always shown with numerator and denominator; `undefined` when the denominator is 0):
  - precision = TP/(TP+FP)
  - recall = TP/(TP+FN)
  - F1 = 2TP/(2TP+FP+FN)
  - benign alert rate = FP/(FP+TN)
  - specificity = TN/(FP+TN)
- **Latency:** distribution (n, median, quartiles, observed range) over true positives only. A benign alert's time is not a detection latency.
- **Coverage:** expected notifications are derived from the ground-truth plan. A write is expected as `modified`; a copy, archive or new file as `created`; a rename as `moved` (at the destination); a delete as `deleted`. The harness reports:
  - exact (path, operation) coverage;
  - path coverage under any operation;
  - missing paths;
  - operation mismatches;
  - duplicate notifications;
  - unexpected paths;
  - planned versus matching notification counts, because repeated edits of one file collapse to one expected pair.

  Coverage is measured on the events CipherSentry's folder monitor **delivers to the Controller**. That is after the monitor's own filtering: for example, it suppresses a `modified` notification whose sampled content matches the last sample. It therefore shows whether each **expected file path and operation from the ground truth** reached the risk engine at least once. It is **not** a measure of complete Windows notification or kernel write coverage. The harness does not see raw OS notifications or write calls, and the current monitoring system cannot prove that none were missed.
- **Evidence completeness:**
  - baseline completeness;
  - late or unscored observations;
  - stale events;
  - dropped notifications;
  - maximum monitor lag;
  - the fraction of scored events with comparable before/after entropy;
  - collector warnings;
  - the engine's missing-evidence list at the peak assessment.
- **Indicator summaries:** per-indicator points at each run's peak assessment, summarized by label.
- **Not calculated:** containment effectiveness, file impact under containment, and false-positive intervention rate. The harness never contains anything, and folder events have no verified writer.

## Outputs

`--output DIR` must be new or empty. It receives:

- `manifest.json`: experiment ID, environment, frozen policy and hash, label rule, criterion, parameters, workload definitions and the seeded run order;
- `runs/NNN-<workload>-r<repeat>.json`: one complete record per run, including:
  - status;
  - outcome, peak score and indicator points;
  - first High;
  - timings and coverage;
  - evidence and safety blocks;
  - the full ground-truth action log;
  - the compact list of observed events;
- `runs.csv`: one row per run;
- `summary.json`: overall and per-split confusion matrices, metrics, outcome tables and distributions, plus failed runs;
- `evidence/` (with `--export-evidence`): each run's SQLite JSON export, which `python -m scripts.ablation` can replay.

## Reproduction

From the repository on Windows (standard user):

```powershell
$py = "<venv>\Scripts\python.exe"
& $py -m scripts.evaluate --list
& $py -m scripts.evaluate --output <new-results-dir> --split all --repeats 1      # pilot
& $py -m scripts.evaluate --output <new-results-dir> --split heldout --repeats 10 # final study
```

`--policy` selects the detection-rule policy. The default, `m3-v1`, is the Milestone 3 baseline; `m3b-v2` is experimental. The selected version is recorded in every output (format 2). See [DETECTION_RULE_VERSIONS.md](DETECTION_RULE_VERSIONS.md).

Format 2 run records also store `block_entropy` evidence for each observed event, or `null` when it was not collected. This evidence is not scored. The M3 pilot records (format 1) have no block evidence. See [BLOCK_ENTROPY_EVIDENCE.md](BLOCK_ENTROPY_EVIDENCE.md).

Seeds are derived as `workload_seed × 1000 + repeat`, and the run order is shuffled with `--order-seed` (default 20261118). Re-running with the same commit, arguments and seeds regenerates identical fixtures, plans and payload bytes. Timing-dependent outcomes can still vary between runs and machines; that variation is what the repeats measure.

## Windows pilot, 18 November 2026

This is a **small pilot: one repeat of each of the 32 variants**. It shows how the harness and the frozen rules behave; it does not establish accuracy. Raw results are in [validation/evaluation-pilot-windows-20261118/](validation/evaluation-pilot-windows-20261118/) (`manifest.json`, `summary.json`, `runs.csv`, one JSON file per run).

**Conditions:**
- **Host:** Windows 11 (10.0.26200), 20 logical CPUs, Python 3.12.10, PySide6 6.8.3, watchdog 6.0.0, psutil 7.0.0.
- **Code:** commit `8fe7e19` with no tracked changes to the code under test.
- **Policy:** frozen policy SHA-256 `dce51df4…`.
- **Run settings:** standard user, alert-only, seeded order 20261118, fixtures in the system temporary folder.

**Integrity of the runs:**
- 32/32 runs completed and every safety check passed.
- Every run had a complete baseline and 0 pre-workload events.
- Clock alignment was valid in all runs (handshake offset 0.12–0.65 ms).
- No notifications were dropped, late or unscored.
- Every expected (path, operation) pair from the ground truth was delivered to the Controller at least once in every run. This is expected-path coverage, not proof of complete kernel-level notification coverage (see Coverage above).
- Delivery delay: median 0.098 s (range 0.085–0.126 s).

| Criterion | TP | FP | TN | FN | Precision | Recall | F1 | Benign alert rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **High (primary), all 32** | 7 | 2 | 16 | 7 | 7/9 = 0.778 | 7/14 = 0.500 | 14/23 = 0.609 | 2/18 = 0.111 |
| High, development (16) | 3 | 1 | 8 | 4 | 3/4 = 0.750 | 3/7 = 0.429 | 6/11 = 0.545 | 1/9 = 0.111 |
| High, held-out (16) | 4 | 1 | 8 | 3 | 4/5 = 0.800 | 4/7 = 0.571 | 8/12 = 0.667 | 1/9 = 0.111 |
| Uncertain or High (sensitivity only), all 32 | 12 | 7 | 11 | 2 | 12/19 = 0.632 | 12/14 = 0.857 | — | 7/18 = 0.389 |

| Label | High | Uncertain | Low | No scored evidence |
| --- | --- | --- | --- | --- |
| benign (18 runs) | 2 | 5 | 11 | 0 |
| suspicious (14 runs) | 7 | 5 | 2 | 0 |

**Detection latency** (true positives, n = 7) was 0.36–0.90 s for rapid workloads. One slow run (S04 held-out) was detected at 8.16 s. Median 0.51 s.

**What explains each error**, from the indicator points at each run's peak (F/E/O/S = frequency/entropy/operations/spread):

- **False positives: B09 (both variants), score 100.** The authorized in-place encryption is behaviourally identical to S01. This is the expected limit of behaviour-only folder monitoring, not a calibration finding.
- **S06 replace-and-delete (both variants): Low, 25.** Replacements arrive as `created` events with no prior entropy baseline, and originals as `deleted`. Frequency, entropy and spread therefore score 0; only repeated operations score. This confirms the known blind spot for create-then-delete patterns.
- **S07 partial overwrite (both variants): Uncertain, 65.** The whole file fits in the 64 KiB sample. Overwriting only its first 4 KiB raised sampled entropy from about 4.3 to 5.42–5.89 bits/byte, a rise of 1.16–1.58 bits. That meets the 1-bit rise condition, but not the 7 bits/byte floor, so no file counted as an entropy rise and entropy scored 0.
- **Composition of the first High:** in every true positive except S03, the first High was 80 = 10/35/25/10. That needs at least 6 modifications, at least 3 qualifying entropy rises, at least 4 unique files and at least 3 folders within 10 s. S03 (one folder) reached 82 = 22/35/25/0 after 8 files.
- **S05 low-volume burst (both variants): Uncertain, 62–67.** Five files stay in the lowest frequency band and the lower operations band.
- **S04 slow overwrite: Uncertain, 67 (development) vs High, 80 (held-out).** The held-out variant writes slightly faster and more files, so enough evidence accumulates within the 10 s window.
- **Benign Uncertain (not alerts under the primary criterion):**
  - B03 bulk text rewrite and B08 media re-export both reached 65 from activity signals alone (30/0/25/10). That is 10 points below High; entropy was the only signal that kept them below High.
  - B01 held-out reached 40, exactly the Uncertain threshold.

**Notes on coverage:**
- Duplicate notifications in B01, B02 and B07 are by design: the same file is edited repeatedly, and planned and matching counts are equal, so no repeat was coalesced away.
- In S02, each file was renamed milliseconds after being overwritten. When the monitor sampled the `modified` notification after its 60 ms debounce, the file had already moved, so it had no after-sample. In 27 of 30 (development) and 35 of 40 (held-out) files, two such `modified` events were delivered rather than one. The entropy rise was observed on the `moved` event instead: before is the original text, after is the renamed file. Only the 30/87 and 40/115 `moved` events had comparable entropy.
- Creation-only workloads (B04–B06, S06) have no comparable entropy by design.

**What the pilot does not show:**
- statistical confidence: one repeat per variant;
- behaviour under real applications, concurrency or other hosts;
- anything about containment.

The development/held-out comparison is descriptive: no parameter was tuned on either split.

## Threats to validity and limitations

- **Synthetic workloads.** Seeded pseudorandom overwrites are easier than adversarial software, which can throttle, write partially, mimic benign tools or spread over time. Benign workloads are simple models of real applications (editors, backup and archive tools), not the applications themselves.
- **Labels by design intent.** B09 is behaviourally identical to S01; an alert there is the expected limitation of behaviour-only detection, not a tuning target.
- **Folder path only.** Events are unattributed (`folder:unattributed`). Concurrent benign activity in the watched folder would merge into the same evidence group; the harness runs one workload at a time and checks for pre-workload events.
- **One host and storage device.** Antivirus scanning, disk speed and load affect notification delay and coverage. Endpoint security settings were not queried.
- **Notification-level coverage.** Path notifications are not kernel write calls, and the monitor filters notifications whose sampled content did not change. Coverage shows that each expected path and operation reached the engine, not that every Windows notification or write was observed. Coalesced repeats are only visible through the planned/matching counts.
- **Development/held-out split.** Held-out variants use the same 16 workload families with different seeds, file counts, folder counts and rates. They test variation in parameters, not unseen behaviours. Both splits were designed together and run in the same pilot, and no parameter was tuned on either; the split is in place for future calibration.
- **Published failed-run records.** A failed run keeps `fixtures_retained_at` and a traceback, which contain local absolute paths. The pilot had no failed runs. Review any future failed-run records before publishing them.
- **Small pilot.** One repeat per variant shows behaviour but supports no statistical claim. Use at least ten repeats per held-out variant for the final study.
- **Frozen, uncalibrated rules.** The weights and thresholds are development placeholders, not validated probabilities.
- **Detection latency** is measured until the Controller produces the assessment. It excludes GUI rendering and the user's reaction.

## Recommendations for the final evaluation

1. Keep this policy frozen. Run the **held-out split with at least ten repeats** per variant (`--split heldout --repeats 10`), and report distributions and per-variant outcome counts rather than a single accuracy figure.
2. If any rule is changed in response to these findings (for example, the create/delete blind spot), change it only on development runs, record the new policy, and evaluate it on **new** held-out variants. The current held-out results must then be described as exploratory.
3. Add real benign applications (an editor, Windows backup or `robocopy`, 7-Zip, a build) through a separate harness that records their ground truth, and include concurrent benign plus suspicious runs.
4. Repeat on a second host or a VM with a recorded antivirus configuration. Add overhead sampling (CPU, memory) per the evaluation plan.
5. Report containment separately, only with independently verified process-state evidence from the lab worker; this harness deliberately does not measure it.
