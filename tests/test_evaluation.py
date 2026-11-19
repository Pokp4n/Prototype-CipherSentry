"""Milestone 3: labelled evaluation workloads, metrics and harness.

Workloads only touch generated fixtures in pytest temporary directories. The
two harness runs use the real folder monitor in alert-only mode; no lab
worker, containment, ETW collector or elevation is involved.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from ciphersentry.engine import RiskConfig
from scripts import eval_metrics as m
from scripts import eval_workloads as w
from scripts import evaluate


# --- catalog and independent labels ----------------------------------------

def test_catalog_ids_seeds_and_splits_are_unique_and_paired():
    specs = w.catalog()
    ids = [s.workload_id for s in specs]
    assert len(ids) == len(set(ids))
    assert len({s.seed for s in specs}) == len(specs)
    bases = {i.split("/")[0] for i in ids}
    for base in bases:
        assert {f"{base}/dev", f"{base}/heldout"} <= set(ids)
    assert {s.label for s in specs} == {w.BENIGN, w.SUSPICIOUS}
    assert {s.split for s in specs} == {w.DEVELOPMENT, w.HELDOUT}
    assert all(s.label_rationale and s.description for s in specs)


def test_frozen_policy_matches_the_current_engine_defaults():
    # If engine defaults change, this fails instead of silently evaluating a new policy.
    assert w.FROZEN_POLICY == RiskConfig().to_dict()
    assert len(w.policy_sha256(w.FROZEN_POLICY)) == 64


def test_evaluation_policies_default_to_m3_v1_and_are_valid_engine_configs():
    assert w.DEFAULT_POLICY_VERSION == "m3-v1"
    assert set(w.EVALUATION_POLICIES) == {"m3-v1", "m3b-v2"}
    baseline = w.evaluation_policy("m3-v1")
    assert baseline["policy"] == w.FROZEN_POLICY and baseline["status"] == "frozen"
    experimental = w.evaluation_policy("m3b-v2")
    assert experimental["status"] == "experimental"
    assert experimental["policy"]["rules_version"] == "m3b-v2"
    for version in w.EVALUATION_POLICIES:
        policy = w.evaluation_policy(version)["policy"]
        assert RiskConfig.from_dict(policy).to_dict() == policy  # canonical, loadable by the app
    baseline["policy"]["high_threshold"] = 1  # callers get a copy, never the registry itself
    assert w.FROZEN_POLICY["high_threshold"] == 75
    with pytest.raises(ValueError, match="Unknown evaluation policy"):
        w.evaluation_policy("m3-v9")


def test_cli_lists_policies_and_refuses_unknown_ones(capsys):
    assert evaluate.main(["--list", "--workload", "S05-low-volume-burst"]) == 0
    listing = capsys.readouterr().out
    assert "policy m3-v1" in listing and "(default)" in listing.split("policy m3b-v2")[0]
    assert "policy m3b-v2" in listing and "experimental" in listing
    with pytest.raises(SystemExit):
        evaluate.main(["--list", "--policy", "m3-v9"])


def test_experiment_refuses_an_unknown_policy_before_writing(tmp_path):
    spec = w.select(w.catalog(), "development", ["S05-low-volume-burst"])
    with pytest.raises(ValueError, match="Unknown evaluation policy"):
        evaluate.run_experiment(spec, tmp_path / "out", policy_version="m3-v9")
    assert not (tmp_path / "out").exists()


def _replaced_text_fixtures(spec):
    """Pre-existing low-entropy documents whose original content the plan destroys."""
    text = {f["path"] for f in w.build_fixtures(spec) if f["kind"] == "text"}
    destroyed = set()
    for step in w.build_plan(spec):
        for action in step["actions"]:
            if action["op"] in {"write_random", "overwrite_prefix", "delete"} and action["path"] in text:
                destroyed.add(action["path"])
    return destroyed


@pytest.mark.parametrize("spec", w.catalog(), ids=lambda s: s.workload_id)
def test_labels_follow_the_design_rule_not_a_score(spec):
    destroyed = _replaced_text_fixtures(spec)
    if spec.label == w.SUSPICIOUS:
        assert len(destroyed) >= 3
    elif spec.family == "authorized_encryption":
        assert len(destroyed) >= 3  # same behaviour; benign only by explicit authorization
        assert "authorized" in spec.label_rationale.lower()
    else:
        assert destroyed == set()


def test_select_by_split_and_base_id():
    specs = w.catalog()
    held = w.select(specs, "heldout")
    assert held and all(s.split == w.HELDOUT for s in held)
    chosen = w.select(specs, "all", ["S01-rapid-overwrite-multidir"])
    assert [s.workload_id for s in chosen] == ["S01-rapid-overwrite-multidir/dev", "S01-rapid-overwrite-multidir/heldout"]


# --- deterministic generation ----------------------------------------------

def test_plans_and_payloads_are_deterministic_per_seed():
    spec = w.select(w.catalog(), "development", ["S01-rapid-overwrite-multidir"])[0]
    assert w.build_plan(spec) == w.build_plan(spec)
    other = w.WorkloadSpec(**{**spec.to_dict(), "seed": spec.seed + 1})
    assert w.build_plan(other) != w.build_plan(spec)  # shuffled order depends on the seed
    assert w.random_bytes(7, "a", 64) == w.random_bytes(7, "a", 64) != w.random_bytes(8, "a", 64)
    assert w.text_bytes(1, 2) == w.text_bytes(1, 2) and len(w.text_bytes(1, 2)) == w.TEXT_SIZE_TARGET


def test_expected_observations_map_each_operation():
    plan = [{"step": 0, "delay": 0, "actions": [
        {"op": "write_random", "path": "a/x.txt"}, {"op": "rename", "path": "a/x.txt", "dest": "a/x.locked"}]},
        {"step": 1, "delay": 0, "actions": [{"op": "copy", "path": "a/y.txt", "dest": "backup/a/y.txt"},
                                             {"op": "delete", "path": "a/y.txt"}]}]
    assert w.expected_observations(plan) == [
        {"path": "a/x.txt", "operation": "modified"}, {"path": "a/x.locked", "operation": "moved"},
        {"path": "backup/a/y.txt", "operation": "created"}, {"path": "a/y.txt", "operation": "deleted"}]


# --- confinement and fixture isolation -------------------------------------

@pytest.mark.parametrize("bad", ["../escape.txt", "/abs.txt", "\\abs.txt", "C:/x.txt", "a/../../x.txt", "a/../x", ""])
def test_unsafe_paths_are_rejected(tmp_path, bad):
    with pytest.raises(ValueError):
        w._confined(tmp_path, bad)


def test_normalised_relative_path_stays_inside_root(tmp_path):
    assert w._confined(tmp_path, "./x") == tmp_path / "x"


def test_symlinked_fixture_directory_is_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    watched = tmp_path / "watched"
    watched.mkdir()
    try:
        (watched / "dept-01").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Creating symlinks needs Developer Mode or elevation on this host")
    with pytest.raises(ValueError):
        w._confined(watched, "dept-01/doc.txt")


def test_fixture_creation_never_replaces_existing_files(tmp_path):
    spec = w.select(w.catalog(), "development", ["S05-low-volume-burst"])[0]
    w.create_fixtures(tmp_path, spec)
    with pytest.raises(FileExistsError):
        w.create_fixtures(tmp_path, spec)


@pytest.mark.parametrize("base", ["S02-overwrite-and-rename", "S06-replace-and-delete", "B04-backup-copy",
                                  "B05-zip-archive", "S07-partial-overwrite", "B07-log-append"])
def test_plan_execution_stays_inside_the_fixture_directory(tmp_path, base):
    spec = w.select(w.catalog(), "development", [base])[0]
    sentinel = tmp_path / "outside.txt"
    sentinel.write_bytes(b"untouched")
    watched = tmp_path / "watched"
    watched.mkdir()
    fixtures = w.create_fixtures(watched, spec)
    plan = [{**step, "delay": 0} for step in w.build_plan(spec)]
    records = []
    done = w.run_plan(watched, spec.seed, plan, records.append)
    assert done == sum(len(step["actions"]) for step in plan) == len(records)
    assert sentinel.read_bytes() == b"untouched"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["outside.txt", "watched"]
    for path in watched.rglob("*"):
        assert path.resolve().is_relative_to(watched.resolve())
    assert all(r["started_perf"] <= r["completed_perf"] for r in records)
    written = [r["entropy_written"] for r in records if r["entropy_written"] is not None]
    if spec.family == "partial_overwrite":
        # By design only a prefix changes: whole-file entropy rises but stays below 7 bits/byte.
        assert written and all(5.0 < value < 7.0 for value in written)
    elif spec.label == w.SUSPICIOUS:
        assert any(value > 7 for value in written)
    assert len(fixtures) == len(w.build_fixtures(spec))


def test_writer_refuses_a_directory_without_the_ownership_marker(tmp_path):
    (tmp_path / "watched").mkdir()
    with pytest.raises((OSError, ValueError)):
        w.check_owned_root(tmp_path)
    (tmp_path / w.MARKER).write_text(json.dumps({"kind": "something else"}), encoding="utf-8")
    with pytest.raises(ValueError):
        w.check_owned_root(tmp_path)
    (tmp_path / w.MARKER).write_text(json.dumps({"kind": w.MARKER_KIND}), encoding="utf-8")
    assert w.check_owned_root(tmp_path) == tmp_path / "watched"


# --- metrics ---------------------------------------------------------------

def run(label, level, *, latency=None, status="completed", split="heldout", coverage=1.0, late=0, peak=None):
    return {"run_id": f"{label}-{level}", "workload_id": "x/heldout", "label": label, "split": split,
            "status": status, "max_level": level, "peak_score": peak,
            "timings": {"detection_latency_s": latency, "delivery_delay_s": 0.1},
            "coverage": {"exact_coverage": m.ratio(int(coverage * 4), 4)},
            "evidence": {"late_observations": late, "dropped_notifications": 0},
            "peak_signals": [{"name": "Entropy change", "points": 35}]}


def test_ratio_reports_undefined_instead_of_zero():
    assert m.ratio(0, 0) == {"value": None, "numerator": 0, "denominator": 0, "display": "0/0 = undefined"}
    assert m.ratio(1, 4)["value"] == 0.25


def test_uncertain_is_not_a_detection_under_the_primary_criterion():
    assert m.predicted_positive("High") and not m.predicted_positive("Uncertain")
    assert m.predicted_positive("Uncertain", m.SENSITIVITY_CRITERION)
    assert not m.predicted_positive(None) and m.outcome_level(None) == "No scored evidence"
    with pytest.raises(ValueError):
        m.predicted_positive("High", "other")


def test_confusion_and_metrics_with_known_counts():
    runs = [run("suspicious", "High", latency=1.0), run("suspicious", "High", latency=3.0),
            run("suspicious", "Uncertain"), run("suspicious", None),
            run("benign", "High"), run("benign", "Low"), run("benign", "Uncertain")]
    counts = m.confusion(runs)
    assert counts == {"TP": 2, "FP": 1, "TN": 2, "FN": 2}
    metrics = m.detection_metrics(counts)
    assert metrics["precision"]["value"] == pytest.approx(2 / 3)
    assert metrics["recall"]["value"] == pytest.approx(0.5)
    assert metrics["f1"]["value"] == pytest.approx(4 / 7)
    assert metrics["benign_alert_rate"]["value"] == pytest.approx(1 / 3)
    assert m.confusion(runs, m.SENSITIVITY_CRITERION) == {"TP": 3, "FP": 2, "TN": 1, "FN": 1}
    table = m.level_table(runs)
    assert table["suspicious"] == {"High": 2, "Uncertain": 1, "Low": 0, "No scored evidence": 1}


def test_zero_denominators_are_undefined():
    metrics = m.detection_metrics({"TP": 0, "FP": 0, "TN": 3, "FN": 0})
    assert metrics["precision"]["value"] is None and metrics["recall"]["value"] is None
    assert metrics["f1"]["value"] is None
    assert metrics["benign_alert_rate"]["value"] == 0.0


def test_summary_excludes_failed_runs_and_uses_only_true_positive_latencies():
    runs = [run("suspicious", "High", latency=2.0), run("suspicious", "Low"),
            run("benign", "High", latency=9.9), run("benign", None, status="failed")]
    runs[-1]["error"] = "TimeoutError: boom"
    summary = m.summarize(runs)
    assert summary["completed_runs"] == 3
    assert summary["failed_runs"][0]["error"] == "TimeoutError: boom"
    latency = summary["overall"]["detection_latency_s_true_positives"]
    assert latency["n"] == 1 and latency["median"] == 2.0  # the benign alert's time is not a detection latency
    assert summary["overall"]["confusion"] == {"TP": 1, "FP": 1, "TN": 0, "FN": 1}


def test_distribution_handles_empty_and_single_values():
    assert m.distribution([])["median"] is None
    assert m.distribution([None, 2.0])["median"] == 2.0
    assert m.distribution([1.0, 2.0, 3.0, 4.0])["p25"] == pytest.approx(1.75)


def test_coverage_counts_missing_duplicates_mismatches_and_case():
    expected = [{"path": "a/x.txt", "operation": "modified"}, {"path": "a/x.txt", "operation": "modified"},
                {"path": "a/y.txt", "operation": "modified"}, {"path": "a/z.locked", "operation": "moved"},
                {"path": "b/w.txt", "operation": "deleted"}]
    observed = [{"path": "A\\X.TXT", "operation": "modified"}, {"path": "a/x.txt", "operation": "modified"},
                {"path": "a/x.txt", "operation": "modified"}, {"path": "a/z.locked", "operation": "created"},
                {"path": "tmp/other.tmp", "operation": "created"}]
    result = m.match_coverage(expected, observed)
    assert result["planned_notifying_actions"] == 5
    assert result["expected_notifications"] == 4
    assert result["observed_exact"] == 1
    assert result["observed_path_any_operation"] == 2
    assert result["missing"] == ["deleted:b/w.txt", "modified:a/y.txt"]
    assert result["operation_mismatch"] == ["moved:a/z.locked"]
    assert result["duplicate_notifications"] == 2
    assert result["unexpected_paths"] == ["tmp/other.tmp"]
    assert m.match_coverage(expected, [])["exact_coverage"]["display"] == "0/4 = 0.000"


# --- harness safety --------------------------------------------------------

def test_cleanup_refuses_directories_it_does_not_own(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    stranger = workspace / "cs-eval-stranger"
    stranger.mkdir()
    with pytest.raises((OSError, RuntimeError, ValueError)):
        evaluate._remove_run_root(stranger, workspace)
    elsewhere = tmp_path / "cs-eval-elsewhere"
    elsewhere.mkdir()
    (elsewhere / w.MARKER).write_text(json.dumps({"kind": w.MARKER_KIND}), encoding="utf-8")
    with pytest.raises(RuntimeError):
        evaluate._remove_run_root(elsewhere, workspace)
    assert stranger.exists() and elsewhere.exists()


def test_experiment_refuses_unsafe_output_or_workspace(tmp_path):
    spec = w.select(w.catalog(), "development", ["S05-low-volume-burst"])
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "keep.txt").write_text("x")
    with pytest.raises(ValueError, match="not empty"):
        evaluate.run_experiment(spec, busy)
    with pytest.raises(ValueError, match="outside the repository"):
        evaluate.run_experiment(spec, tmp_path / "out", workspace=evaluate.REPO / "tmp-eval")
    assert not (evaluate.REPO / "tmp-eval").exists()


@pytest.fixture(scope="module")
def qt_app():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_end_to_end_run_records_ground_truth_and_stays_alert_only(tmp_path, qt_app):
    spec = w.select(w.catalog(), "development", ["S05-low-volume-burst"])[0]
    workspace = tmp_path / "ws"
    result = evaluate.run_once(qt_app, spec, 0, workspace, run_id="t1")
    assert result["status"] == "completed", result.get("traceback") or result.get("error")
    assert result["safety"]["ok"] is True
    assert result["safety"]["response_mode"] == "alert_only"
    assert result["safety"]["lab_worker_started"] is False
    assert result["safety"]["etw_candidate_records"] == 0
    assert result["safety"]["forbidden_audit_actions"] == []
    assert len(result["ground_truth"]["actions"]) == result["planned_actions"] == 5
    assert result["evidence"]["baseline_complete"] is True
    assert result["evidence"]["pre_workload_events"] == 0
    assert result["timings"]["clock_alignment_ok"] is True
    assert result["coverage"]["expected_notifications"] == 5
    assert result["writer_exit_code"] == 0 and result["writer_running_after_cleanup"] is False
    assert result["max_level"] in {"High", "Uncertain", "Low", None}  # outcome is measured, not asserted
    assert result["policy_version"] == "m3-v1" and result["format_version"] == 2  # default unchanged
    assert list(workspace.iterdir()) == []  # fixtures removed after a completed run


def test_policy_mismatch_fails_the_run_and_preserves_diagnostics(tmp_path, qt_app, monkeypatch):
    monkeypatch.setitem(w.EVALUATION_POLICIES, "m3-v1",
                        {**w.EVALUATION_POLICIES["m3-v1"], "policy": {**w.FROZEN_POLICY, "high_threshold": 80}})
    spec = w.select(w.catalog(), "development", ["S05-low-volume-burst"])[0]
    workspace = tmp_path / "ws"
    result = evaluate.run_once(qt_app, spec, 0, workspace, run_id="t2")
    assert result["status"] == "failed"
    assert result["error"].startswith("PolicyMismatch")
    assert "Traceback" in result["traceback"]
    retained = Path(result["fixtures_retained_at"])
    assert retained.is_dir() and (retained / w.MARKER).is_file()  # failed-run diagnostics are kept
    assert "writer_exit_code" not in result  # the writer was never started


def test_experiment_with_m3b_v2_records_the_selected_policy_everywhere(tmp_path, qt_app):
    import csv
    spec = w.select(w.catalog(), "development", ["S05-low-volume-burst"])
    out = tmp_path / "out"
    summary = evaluate.run_experiment(spec, out, workspace=tmp_path / "ws", app=qt_app,
                                      progress=lambda *_: None, policy_version="m3b-v2")
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["format_version"] == 2
    assert manifest["policy_version"] == "m3b-v2" and manifest["policy_status"] == "experimental"
    assert manifest["frozen_policy"] == w.M3B_V2_POLICY
    assert manifest["frozen_policy_sha256"] == w.policy_sha256(w.M3B_V2_POLICY) != w.policy_sha256(w.FROZEN_POLICY)
    assert summary["policy_version"] == "m3b-v2" and summary["completed_runs"] == 1
    run = json.loads(next((out / "runs").glob("*.json")).read_text(encoding="utf-8"))
    assert run["policy_version"] == "m3b-v2" and run["status"] == "completed"
    assert run["safety"]["ok"] and run["safety"]["live_policy_matches_frozen"]
    assert run["safety"]["response_mode"] == "alert_only"
    rows = list(csv.DictReader((out / "runs.csv").open(encoding="utf-8")))
    assert [row["policy_version"] for row in rows] == ["m3b-v2"]
    assert list((tmp_path / "ws").iterdir()) == []
