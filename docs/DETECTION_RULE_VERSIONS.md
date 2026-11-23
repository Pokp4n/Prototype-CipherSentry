# Detection-rule versions

CipherSentry's risk policy has two parts:

- **Numbers:** window, thresholds, weights and enabled indicators.
- **Rules:** how folder evidence becomes indicator values.

Rule versioning lets experimental rules be added, switched on and off, and compared without changing or contaminating the Milestone 3 baseline.

**Status (M3B Step 0):** the versioning mechanism is **implemented and tested**. **No experimental rule is implemented yet**, so `m3b-v2` currently scores exactly like `m3-v1`. Weights, thresholds and indicator formulas are unchanged.

**Step 1:** the folder monitor also records [block-level entropy evidence](BLOCK_ENTROPY_EVIDENCE.md). It is evidence only. No rule version reads it, so scores under both versions are unchanged.

## Versions

| Version | Status | Meaning |
| --- | --- | --- |
| `m3-v1` | Frozen | The rules evaluated in the [Milestone 3 pilot](EVALUATION_HARNESS.md#windows-pilot-18-november-2026). The default everywhere. Its behaviour must never change. |
| `m3b-v2` | Experimental | Identical to `m3-v1` except for the rules named in `experimental_rules`. Each rule is opt-in by name. |

The versions are defined in `ciphersentry/engine.py` (`RULE_VERSIONS`, `EXPERIMENTAL_RULES`). `RiskConfig` carries two fields:
- `rules_version`: default `"m3-v1"`;
- `experimental_rules`: default empty; only allowed with `m3b-v2`, and only names registered in `EXPERIMENTAL_RULES`.

Unknown versions, unregistered rules, duplicates, and rules under `m3-v1` are refused.

## Backward compatibility guarantees

- **Canonical serialization.** For `m3-v1`, `RiskConfig.to_dict()` is exactly the Milestone 3 dictionary, with no added keys. Settings files, stored assessments and evidence exports written with `m3-v1` are therefore unchanged.
- **M3 fingerprint.** The M3 policy SHA-256 is still `dce51df451e15491ee075618bfe0c09c9268f8f8343686ce9102477f85d6bc97`. It is pinned by a test against the committed pilot manifest.
- **Migration.** A configuration without rule fields (every existing `settings.json`, export or manifest) loads as `m3-v1`.
- **Fail closed.** A settings file naming an unknown rule version is not loaded. The app uses the `m3-v1` alert-only defaults and records a `settings_migration` warning.
- **No silent version change.** The GUI policy form has no rule controls. A weight or threshold change keeps the current rule version; only an explicit `rules_version` changes it.
- **Exact M3 reproduction.** A test replays all 1,278 observed events from the 32 committed pilot runs through the engine. Every recorded level and score is reproduced under `m3-v1`, and under `m3b-v2` with no rules enabled.
- **Older code** does not understand `m3b-v2` settings. It would reject them and fall back to its defaults, which are `m3-v1`.

## How a future rule is added, enabled and disabled

1. Register the rule name and a one-line description in `EXPERIMENTAL_RULES`.
2. Implement it in the engine behind `config.uses_rule("<name>")`. With the rule off, the code path must be exactly the `m3-v1` path.
3. Add tests:
   - the rule changes the intended evidence when on;
   - nothing changes when it is off;
   - the M3 replay test still passes under `m3-v1`.
4. Enable it with `{"rules_version": "m3b-v2", "experimental_rules": ["<name>"]}` in the risk configuration: in an app settings file, an ablation `--config` file, or an evaluation policy entry. Remove the name to disable it.

Each combination of enabled rules has its own policy fingerprint, so results from different rule sets cannot be mixed unnoticed.

## How versions are compared

- **Live evaluation:** `python -m scripts.evaluate --output <new-dir> --policy m3b-v2`.
  - The default is `--policy m3-v1`, which runs exactly as in Milestone 3, using the app's built-in defaults.
  - Other policies are applied through the app's own settings file, in alert-only mode.
  - The harness refuses to run if the live policy differs from the selected one.
  - Output format 2 records `policy_version` in the manifest, every run record, the summary and the CSV. Format 1 records (the M3 pilot) have no policy version and used `m3-v1`.
- **Paired replay (preferred for comparisons):**
  - Record runs once with `--export-evidence`.
  - Replay the same evidence through each policy with `python -m scripts.ablation --config <policy.json>`.
  - Identical observations then differ only in the rules, so timing variation between live runs cannot affect the comparison.
- **Policy status:** `m3b-v2` is `experimental` in the harness's policy registry (`scripts/eval_workloads.py`), and manifests record that status. Its results are development evidence until the rules are frozen and evaluated on new held-out workloads, as planned for M3B.
