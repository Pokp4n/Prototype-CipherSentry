# Block-level entropy evidence

**Status (M3B Step 1):** the folder monitor collects block-level entropy, records it with each event and includes it in exports. This is **implemented and tested**, but it is **evidence only**. It contributes nothing to any score, alert or response under `m3-v1` or `m3b-v2`. Weights, thresholds and indicator formulas are unchanged.

When the monitor is backlogged, block measurement is **deferred** and recorded as missing (`deferred_under_load`). This protects the freshness of the scored whole-sample evidence. Under sustained overload, most block evidence is therefore unavailable. See [Adaptive collection under monitoring overload](#adaptive-collection-under-monitoring-overload).

## What it measures

The monitor reads at most the first **64 KiB** of a file and calculates one Shannon entropy value for that sample. This whole-sample value is `entropy_before` / `entropy_after`, and it is the value the entropy indicator scores.

Block-level evidence splits the same 64 KiB sample into **4 KiB blocks**, at most 16, and measures the entropy of each block. It then compares each block with the same block in the file's baseline sample.

The difference matters for **localised changes**:

- **Whole-sample entropy** averages over the entire sample. If one 4 KiB region of a 64 KiB document becomes random-looking, the whole-sample value moves only a little.
- **Block entropy** shows which region changed, and by how much.

### Example: one block of a document overwritten

The monitor was given a disposable 64 KiB text file in a temporary folder, and block 5 of that file was overwritten with pseudo-random bytes.

- **Whole sample:** 4.168 → 4.691 bits/byte. That is a rise of about 0.5 bits, below the 1-bit rise and 7-bit level the `m3-v1` entropy rule requires. The `m3-v1` score for this event is 0.
- **Block evidence** recorded with the event (shortened):

```json
{
  "format": "block-entropy-v1",
  "block_size": 4096,
  "before": {"file_size": 65536, "sample_bytes": 65536, "short_read": false,
             "entropy": [4.168, 4.168, 4.167, 4.168, 4.17, 4.168, 4.168, "…"]},
  "before_missing": null,
  "after":  {"file_size": 65536, "sample_bytes": 65536, "short_read": false,
             "entropy": [4.168, 4.168, 4.167, 4.168, 4.17, 7.956, 4.168, "…"]},
  "after_missing": null,
  "blocks": ["unchanged", "unchanged", "unchanged", "unchanged", "unchanged", "changed", "unchanged", "…"],
  "summary": {"changed": 1, "unchanged": 15, "length_changed": 0,
              "before_only": 0, "after_only": 0, "max_rise": 3.788}
}
```

## Format (`block-entropy-v1`)

The field is `block_entropy`. It appears on `FileEvent`, in the SQLite `event_json` column, in JSON exports, and in format 2 evaluation run records.

| Field | Meaning |
| --- | --- |
| `before`, `after` | The baseline and current measurement, or `null` if missing. |
| `file_size` | File size when sampled. Files over 64 KiB are measured only in their first 64 KiB. |
| `sample_bytes` | Bytes actually read, at most 65,536. The final block is shorter when this is not a multiple of 4,096. |
| `short_read` | `true` if fewer bytes were read than the file size reported just before the read. This means the file was probably truncated while being sampled. |
| `entropy` | One value per block, in bits/byte, with three decimals. |
| `before_missing`, `after_missing` | Why a side is missing. Always `null` when the side is present. |
| `blocks` | One status per block index. `null` when either side is missing. |
| `summary` | Counts of each status, plus `max_rise`: the largest signed entropy change among `changed` blocks (`null` if none changed). |

Block statuses:

- **`changed`:** same length, different content.
- **`unchanged`:** same length, same CRC-32. A CRC-32 match means unchanged, with a 1 in 2³² chance of missing a real change.
- **`length_changed`:** the final partial block has a different length. Different lengths are not comparable.
- **`before_only` / `after_only`:** the sample shrank or grew past this block.

A **changed** block can keep exactly the same entropy, for example when bytes are reordered. The status comes from the CRC-32, not from the entropy values.

## How missing evidence is represented

Missing measurements are never replaced by zero or guessed.

| Situation | Representation |
| --- | --- |
| New file, or a file not in the baseline (baseline limit, or unreadable when the baseline was taken) | `before: null`, `before_missing: "not_in_baseline"` |
| Deleted file | `after: null`, `after_missing: "deleted"` |
| File vanished, not a regular file, or the read failed (for example, access denied) | `after: null`, `after_missing: "unreadable"`. The read error is reported as a collector warning, as before. |
| Block collection switched off when that side was sampled | `"not_measured"` |
| That side was sampled while the monitor was backlogged | `"deferred_under_load"`. The file was read and its whole-sample entropy calculated as usual; only the block measurement was skipped. |
| Empty file | Present, with `sample_bytes: 0`, an empty `entropy` list, and an empty `blocks` list |
| File truncated during the read | `short_read: true`. Blocks that were not read are absent, not zero. |

A missing side is **unknown** evidence. It is not evidence of suspicious activity, nor of benign activity.

## Adaptive collection under monitoring overload

**Why it exists.** A sustained-load benchmark (below) showed that measuring blocks on every sample made an already overloaded monitor fall further behind. More observations then arrived after the 10-second evidence window and were stored as Unscored. Block evidence is not scored, while timely whole-sample evidence is. Under overload, block measurement therefore gives way.

**Criterion.** When the monitor takes a notification from its queue, it checks how long that notification has been waiting. If it is older than **2 seconds** (`FolderMonitor.BLOCK_DEFER_AGE_SECONDS`), the monitor is treated as backlogged for that sample.

| Reference point | Value |
| --- | --- |
| Healthy delivery delay, M3 pilot (median / maximum) | 0.10 s / 0.13 s |
| Healthy delivery delay, M1 benchmark at 30 files/s (maximum) | about 0.7 s |
| Window after which observations become Unscored | 10 s |

So 2 seconds means the monitor is clearly behind, while most of the window remains. The value was chosen from these earlier measurements before the benchmark below was run, and it was not tuned to that benchmark.

Queue depth was not used. The number of notifications per file write varies (about 1.9 for ordinary rewrites), and sampling cost varies with file size, so age reflects freshness more directly.

**Behaviour.**

- A backlogged sample still reads the same 64 KiB and calculates the whole-sample entropy with the original function, so the scored value is unchanged.
- Only the extra block measurement is skipped. The event records `"deferred_under_load"` for that side.
- Collection resumes automatically as soon as queued notifications are younger than 2 seconds. There is no other state.
- The stored sample for that file has no blocks. The next event for the same file therefore reports `before_missing: "deferred_under_load"` rather than comparing against stale blocks. Full comparison resumes on the following change.
- `FolderMonitor.block_deferred_count`, also reported as `block_entropy_deferred` in the Controller's monitor health, counts the emitted observations with a deferred side.

**Evidence cost.** The criterion reacts to *any* backlog, not only to backlog caused by block measurement. It does not assume that partial overwrites arrive slowly: a partial overwrite during a backlog loses its block evidence like any other observation (see the mixed-load result below).

## Why it does not change detection yet

Step 1 collects evidence and nothing more:

- **The scoring code never reads `block_entropy`.** Tests replay all 1,278 events from the 32 committed M3 pilot runs twice: once as recorded, and once with every event carrying extreme block evidence (all 16 blocks changed to high entropy). Every recorded level and score is reproduced under `m3-v1`, and under `m3b-v2` with no rules enabled.
- **Alerts and containment are unaffected.** Alerts and response decisions come from the assessment, which does not depend on block evidence. A test confirms that block evidence alone produces no alert and no response.
- **Which notifications become events is unchanged.** The monitor still decides "unchanged file" by whole-sample entropy, size and modification time only.
- **The whole-sample value is unchanged.** It is calculated in the same pass as the blocks but is bit-identical to the original `shannon_entropy(data)`: the same byte counts are summed in the same order with the same expression. A test checks exact equality on 406 varied inputs.
- **The M3 policy fingerprint is unchanged.** It remains `dce51df4…`.
- **Deferral changes no score.** A deferred sample uses the original whole-sample calculation. Tests confirm that deferred evidence, like full evidence, leaves every assessment unchanged and raises no alert or response.

Turning block evidence into a scored rule requires a registered `m3b-v2` experimental rule, tests, and a held-out evaluation. See [DETECTION_RULE_VERSIONS.md](DETECTION_RULE_VERSIONS.md).

## Cost

### Disk and memory

- **File reads:** none extra. Blocks are measured from the bytes the monitor already reads.
- **Baseline memory:** each baseline entry gains a compact sample of up to 16 two-byte entropy values plus 16 four-byte CRC-32 values. Measured at about **267 bytes per file**, or about **1.3 MiB** at the 5,000-file baseline limit.
- **Per-event memory:** the evidence object refers to the samples already held in the baseline rather than copying them. Measured at about **130 bytes per event**. The CRC-32 values stay in memory and are never exported.
- **Storage:**

  | Event | `event_json` size |
  | --- | --- |
  | No block evidence | 262 bytes |
  | Full 16-block comparison | about 1,083 bytes |
  | New file (after side only) | about 639 bytes |

### Processor time (isolated sampling)

**Method.** I ran `FolderMonitor._sample` on disposable fixtures (200 files per type) in a temporary folder, alternating collection off and on, and took the median of 7 rounds. This was one Windows 11 development machine running Python 3.12.10. The benchmark script is not part of the repository.

| Fixture | Off (µs/sample) | On (µs/sample) | Change |
| --- | ---: | ---: | ---: |
| 1 KiB text | 520 | 541 | +4% |
| 16 KiB text | 3,458 | 3,673 | +6% |
| 64 KiB text | 9,190 | 8,908 | within noise |
| 64 KiB random | 7,557 | 9,200 | +22% |
| 1 MiB random (64 KiB sampled) | 7,395 | 9,274 | +25% |

| Other measurement | Off | On | Change |
| --- | ---: | ---: | ---: |
| Baseline build, 1,000 × 64 KiB files | 8.31 s | 8.95 s | +8% |
| Building and recording one event's evidence | — | about 27 µs | — |
| Validating evidence loaded from an export | — | about 180 µs per event | — |

**Why high-entropy data costs more.** A random 4 KiB block contains almost all 256 byte values. Per-block calculations and merging the counts therefore take more work than for text, which uses few distinct values. Two earlier versions were measured on the same fixtures and replaced:

- counting the bytes twice cost +74% to +96% for 64 KiB samples;
- a first single-pass version cost +53% for random data.

**Limitations.**

- The numbers come from one machine, in one session, with warm OS file caches, and repeat measurements varied by several percent. They are not a general performance claim.
- They include file-open and read costs but not watchdog notification delivery.
- The overhead is not zero. For high-entropy files it reduces the monitor's maximum sampling rate by roughly a fifth, which matters for very fast bulk writes. Collection can be switched off with `FolderMonitor.COLLECT_BLOCK_ENTROPY = False`; the monitor then behaves exactly as before Step 1, and events carry no `block_entropy`.

### Sustained load

**Method.**

- **Workload:** the M1 method. Disposable fixtures in 4 folders, written by a writer paced at a fixed rate.
- **Path:** the real Controller (queued delivery, risk engine, SQLite storage, 1-second tick).
- **Counted separately:** Windows file writes, raw watchdog notifications, and observations delivered to the Controller.
- **Order:** collection off and on alternated off-on-on-off to balance machine drift.
- **Environment:** one Windows 11 machine, Python 3.12.10, November 2026. The benchmark scripts are not part of the repository.

**Across all runs:**

- every written file was delivered to the Controller (900 of 900, or 100 of 100);
- no notification was dropped;
- ordinary rewrites produced about 1.9 watchdog notifications per write;
- partial in-place writes produced one notification per write.

**The monitor is over capacity at 60 files/s even with collection off.** It delivered about 30–38 observations per second, so a backlog builds in every 60 files/s run.

**Before adaptive collection** (block measurement on every sample, 60 files/s for 15 s, averages of 2 runs each):

| Workload | Collection | p95 delay | Late (Unscored) |
| --- | --- | ---: | ---: |
| 4 KiB rewrites | off | 8.25 s | 0 |
| 4 KiB rewrites | on | 9.05 s | 0 |
| 64 KiB high-entropy rewrites | off | 14.5 s (10.4 and 18.6) | 344 (94 and 594) |
| 64 KiB high-entropy rewrites | on | 23.1 s | 623 |

In the 64 KiB runs, mean sampling time rose from 14.1 ms to 19.1 ms, and the sampling slowdown alone pushed about 280 extra observations out of the scoring window.

**With adaptive collection** (same method, later session, averages of 2 runs each unless stated):

| Workload | Collection | p95 delay | Late (Unscored) | Block evidence deferred |
| --- | --- | ---: | ---: | ---: |
| 4 KiB rewrites, 60/s | off | 9.05 s (8.38 and 9.72) | 0 | — |
| 4 KiB rewrites, 60/s | on | 9.99 s | 28 (33 and 24) | 77% |
| 64 KiB high-entropy rewrites, 60/s | off | 12.2 s (13.96 and 10.37) | 210 (333 and 86) | — |
| 64 KiB high-entropy rewrites, 60/s | on | 10.9 s | 147 (169 and 125) | 82% |
| Partial overwrites (first 4 KiB of 16 KiB documents), 10/s, 1 run | off | 0.13 s | 0 | — |
| Partial overwrites (first 4 KiB of 16 KiB documents), 10/s, 1 run | on | 0.10 s | 0 | **0%** (100 of 100 compared) |
| Mixed: 64 KiB burst, every 5th write a partial overwrite, 1 run | off | 9.78 s | 0 | — |
| Mixed: 64 KiB burst, every 5th write a partial overwrite, 1 run | on | 10.28 s | 72 | 88% overall; **158 of 180 partial overwrites (88%)** |

**Interpretation.**

- **What improved.** For the 64 KiB workload, the large extra penalty from block collection is gone. The adaptive version was no worse than collection off (the difference is within run-to-run variation). The earlier version added about 280 late observations.
- **What did not improve.** For small 4 KiB files, block measurement was never the bottleneck, so deferring it gains little. A small residual difference remains in that workload and in the single mixed pair: about 0.5–0.9 s at the 95th percentile, and some tens of late observations where collection off had none. The direction was consistent, but the size is within this machine's variation; repeat runs with collection off differed by up to 1.3 s at the 95th percentile.
- **What it costs.** During sustained overload, about 77–88% of observations have no block evidence, including about 88% of partial overwrites hidden inside a burst. When the monitor is healthy, block evidence is collected in full.

This is an **improvement relative to the previous block-enabled implementation, not a solution to the monitor's capacity limit**. The monitor still cannot keep up with sustained 60 files/s, with or without block evidence.

**Future M4 considerations (not implemented):**

- Merge duplicate notifications for the same file. About half of all samples are duplicates that are read and then discarded.
- Reduce the Controller's per-event cost. Each event re-assesses the whole evidence window and commits to SQLite separately.

Both would change how many observations are emitted under load, so they need their own evaluation. A cost-aware variant of the deferral criterion is also possible: never defer one-block samples, where measurement adds almost nothing. It is not implemented, to avoid tuning to this benchmark.

## Compatibility

- Events without block evidence (lab, ETW, older records, or collection switched off) serialize exactly as before. The `block_entropy` key is omitted.
- No SQLite schema change is needed. The evidence is stored in the existing `event_json` column, and exports gain the key only for events that carry it.
- Evidence from exports or IPC is validated strictly when loaded: the exact field set, possible entropy values for each block length, statuses consistent with the measurements, and a summary that matches the blocks. Missing reasons must be one of the documented values, including `deferred_under_load`. Invalid evidence is refused, not repaired. Ablation replay reports the offending event number.
- The committed M3 pilot data is unchanged and has no block evidence.

## How Step 3 may use this evidence (proposed, not implemented)

A future `m3b-v2` experimental rule could count a file as an entropy rise when one or more blocks rise sharply, even if the whole-sample value does not. Example triggers:

- a changed block rising to at least 7 bits/byte by at least 1 bit;
- several changed blocks in one file.

This could address partial or intermittent overwrites that the whole-sample rule misses.

Any such rule must:

1. be registered and switched on by name under `m3b-v2`;
2. leave `m3-v1` untouched;
3. be compared with paired replay of the same recorded evidence;
4. be evaluated on new held-out workloads, including benign high-entropy workloads such as compression, legitimate encryption and media edits, which can also produce high-entropy blocks.

Block evidence cannot see changes beyond the first 64 KiB of a file, and like the whole-sample value it cannot identify which process made a change. It is also largely unavailable while the monitor is overloaded (`deferred_under_load`). Any rule must treat that as unknown and must be evaluated under load as well as at healthy rates.
