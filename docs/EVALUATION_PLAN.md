# CipherSentry evaluation plan

This is a protocol for the experiments required by the proposal, not a report of completed experiments. Automated tests and the built-in lab establish software behaviour within their tested conditions. They do not establish detection accuracy against ransomware or production readiness on Windows.

## Questions and experimental units

Evaluate three connected questions:

1. Does combining behavioural signals distinguish suspicious workloads from legitimate high-I/O workloads better than simple baselines?
2. How does the containment policy trade detection/response delay against file impact and unnecessary intervention?
3. What monitoring and assessment overhead does the endpoint incur?

Use a **workload run** as the primary labelled unit. Define each run's label independently of CipherSentry's score: a controlled suspicious transformation or a selected legitimate task. An individual file notification is not an independent attack sample. For process-level claims, the collector must provide validated process attribution; folder-level runs cannot establish that claim.

## Environment and workload matrix

Record Windows edition/build, VM or physical hardware, allocated CPU/RAM, storage medium, Python and package versions, application revision, policy settings, collector type, data volume, file sizes/types, and workload configuration. Start each run from a documented clean fixture state and record background activity.

| Workload group | Examples | Why it matters |
| --- | --- | --- |
| Quiet and everyday use | Idle monitoring, ordinary document save, small text edits | Establish baseline overhead and common false alarms. |
| Legitimate high I/O | Bulk copy, backup/restore, source build, search indexing | Stress activity-rate and directory-spread features. |
| Legitimate high entropy | Archive creation/extraction and an authorized encryption task on disposable data | Test the overlap explicitly described in the proposal. |
| Controlled suspicious behaviour | Generated fixtures rewritten across directories at different rates, with and without renaming | Exercise the complete decision and response path. |
| Difficult cases | Slow activity, small or partial changes, already-compressed inputs, concurrent benign tasks | Expose weaknesses that the easy lab scenario cannot reveal. |

The built-in suspicious and benign lab scenarios cover only a small part of this matrix. Additional application workloads need their own harness and ground-truth logs. Do not label a workload malicious solely because it produces high entropy.

Use an isolated Windows VM and disposable files for controlled experiments. Keep the built-in worker confined to its generated directory. Real malware is unnecessary for the initial study; any later malware study would need a separately approved institutional lab procedure. Record Defender and other endpoint security settings and interventions because they can confound results; do not silently disable or attribute their actions to CipherSentry.

## Ground truth and time points

The experiment harness should record its own action log, independent of the dashboard. Reconcile completed changes with the final fixture state. Distinguish unique source files from operation counts and renamed destination paths.

Record these time points using a monotonic clock within the measurement process, with a documented common origin for cross-process measurements:

- `t_start`: first suspicious or benign operation in the measured workload, excluding fixture generation.
- `t_observed`: first relevant event received by the collector.
- `t_detected`: first assessment meeting the predeclared detection criterion.
- `t_requested`: containment requested by policy.
- `t_contained`: process suspension or termination independently confirmed.
- `t_end`: completion, experiment timeout, or declared termination of the run.

Wall-clock timestamps are useful for an audit trail but can jump. Worker JSON may remain buffered or queued after suspension, so the last event displayed is not proof of the last physical write. Confirm process state and file state when measuring containment.

## Metrics and definitions

| Metric | Definition and reporting rule |
| --- | --- |
| Detection precision | `TP / (TP + FP)`, where positive means the run crossed the predeclared detection criterion. Report the numerator and denominator; use “undefined” when there are no positive predictions. |
| Detection recall | `TP / (TP + FN)` across labelled suspicious runs. Include undetected and timed-out runs according to the predeclared observation window. |
| Benign alert rate | Benign runs that crossed the detection criterion divided by all evaluated benign runs. Keep this separate from intervention. |
| False-positive intervention rate | Benign runs with a successful containment action divided by all evaluated benign runs. Also report attempted actions and action failures separately. |
| Detection latency | `t_detected - t_start`; also report collector delay `t_observed - t_start`. Undetected runs have no observed detection latency, not zero. |
| Containment latency | `t_contained - t_start`; report `t_contained - t_requested` separately to expose process-control delay. Failed containment is a failure outcome, not a fast successful response. |
| File impact | Unique pre-existing fixture files changed by detection and by confirmed containment, using independent harness/file-state evidence. Report total eligible files and fraction affected. Count a modified-and-renamed file once. |
| Post-request impact | Additional unique files changed between `t_requested` and `t_contained`; this captures in-flight work and response delay. |
| Resource overhead | Sample CPU, resident memory, and applicable I/O for the full monitor process tree at a fixed stated interval. Report duration, median/percentiles, and observed sample maximum. |
| Workload slowdown | Compare elapsed workload time with monitoring off/on using matched fixture sets and repeated runs. Report distributions and the definition of relative slowdown. |
| Evidence quality | Lost/dropped events where measurable, inaccessible-file/sample counts, collection failures, missing entropy baselines, and process-attribution coverage. |

An observed sample maximum is not a guaranteed instantaneous peak. Process CPU can exceed 100% under some conventions; state the convention and whether it is normalized by logical CPU count. Keep workload-process resource usage separate from monitor overhead, while also reporting total system impact when relevant.

For a cooperative lab worker, report “synthetic file transformations” rather than claiming encrypted user files or prevented ransomware damage. Automatic intervention restricted to the lab cannot measure arbitrary legitimate-application containment effectiveness; those experiments depend on the later Windows collector and policy.

## Independent attribution and offline ablation tools

Run `python -m scripts.attribution_probe --files 12 --output attribution.json` on the Windows test machine before claiming process-level coverage. The independent writer log supplies ground truth only; it must not be copied into collector records. Report correct, unknown, and incorrect/unstable attribution separately, together with missing/duplicate fixture modifications and delay samples. Path-notification coverage is not exact kernel-write coverage.

Use `python -m scripts.ablation evidence.json --output ablation.json` to replay one exported trace under the baseline and individual indicator removals. An optional `--config policy.json` freezes the chosen numerical rules. Remaining weights are not rescaled. The tool performs no process actions. Its score changes and first-high event offsets are descriptive replay results, not actual execution latency, precision, or recall. Process context currently has no scored rule; disabling it is expected to leave numerical scores unchanged.

## Comparisons and parameter discipline

Compare the full policy against at least a no-containment control and a simple single-signal baseline such as activity rate. Include feature ablations and threshold settings that illustrate the early-response/false-intervention trade-off. Use the same workloads, file sets, and ground-truth definitions for comparisons.

Separate development/calibration workloads from evaluation workloads before tuning. Freeze the window, weights, thresholds, sampling limits, and eligibility rules before the held-out evaluation. Record each policy revision. Do not tune on the test results and then present those same runs as an unbiased final evaluation; create a new held-out set or label the result exploratory.

Repeat each selected condition enough times to show variation; a practical initial plan is at least ten runs per condition, expanded when results are unstable. Randomize or balance condition order, retain individual run outcomes, and report medians and percentile ranges or suitable uncertainty intervals. Avoid claiming statistical confidence from a handful of demonstrations or treating thousands of file events from one run as thousands of independent trials.

## Run procedure

1. Create a fresh fixture set and an experiment ID. Save the manifest, expected workload label, and policy configuration outside the watched data.
2. Start instrumentation; let monitoring establish its baseline. Record inaccessible files and collection warnings.
3. Run the selected workload and record the independent operation log. Observe the predeclared duration even if no alert occurs.
4. Capture detection and response transitions. Confirm any process action against the registered process identity and actual state.
5. Stop instrumentation, reconcile final files, and export event/assessment/action evidence. Preserve errors and missing data.
6. Close or resume/stop owned experimental processes as appropriate, then restore fresh fixtures for the next run.

An application closing, a PID existing, a graph changing, or a test runner executing zero tests is not a successful end-to-end result. Require observable file changes, the expected assessment explanation, and—when tested—verified cessation and resumption of the owned worker.

## Results to include in the FYP report

Provide the workload matrix, frozen policy, per-condition confusion counts, intervention outcomes, latency and file-impact distributions, overhead, and failure analysis. Include representative explanations for a correct detection and a difficult benign case. State what was tested on Windows and what was only exercised on the development host.

Discuss threats to validity: synthetic workloads are easier than adversarial software; one machine or storage device may not generalize; cooperative telemetry omits collection failures; file sampling can miss changes; concurrency can combine unrelated evidence; other endpoint tools can alter outcomes; and threshold tuning can leak evaluation information. Present these as limits on conclusions, with concrete follow-up experiments where possible.
