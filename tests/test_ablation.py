"""Offline comparisons must preserve policy and avoid invented evaluation claims."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from ciphersentry.engine import FileEvent, RiskConfig, RiskEngine
from ciphersentry.storage import EventStore
from scripts.ablation import run_ablation


def export_fixture(tmp_path: Path) -> Path:
    store = EventStore(tmp_path / "evidence.sqlite3")
    engine = RiskEngine()
    for index in range(16):
        event = FileEvent(1000 + index * .1, f"/fixtures/department{index % 3}/file{index}.txt", "modified",
                          entropy_before=3.0, entropy_after=7.9)
        assessment = engine.ingest(event)
        store.record_event(event, assessment)
    target = tmp_path / "evidence.json"
    store.export_json(target)
    store.close()
    return target


def test_real_export_replay_excludes_only_one_weight_and_has_no_accuracy_claims(tmp_path):
    evidence = export_fixture(tmp_path)
    original = evidence.read_bytes()
    target = tmp_path / "ablation.json"
    report = run_ablation(evidence, target)
    assert evidence.read_bytes() == original
    assert json.loads(target.read_text(encoding="utf-8")) == report
    assert report["event_count"] == 16
    assert len(report["variants"]) == 6
    baseline = report["variants"]["baseline"]
    reduced = report["variants"]["without_entropy"]
    assert baseline["peak_score"] == 100
    assert reduced["peak_score"] == 65
    assert reduced["config"]["weights"] == baseline["config"]["weights"]
    assert "entropy" not in reduced["config"]["enabled_indicators"]
    assert baseline["high_risk_crossings"] == 1
    assert reduced["high_risk_crossings"] == 0
    assert report["variants"]["without_context"]["peak_score_difference_from_baseline"] == 0
    assert baseline["groups"][0]["pid"] is None
    assert baseline["groups"][0]["first_high_event_offset_seconds"] >= 0
    assert "accuracy" not in report
    assert any("not detection accuracy" in note for note in report["limitations"])


def test_mixed_configurations_require_explicit_policy_and_do_not_silently_tune(tmp_path):
    evidence = export_fixture(tmp_path)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    payload["events"][0]["assessment"]["config"] = RiskConfig(high_threshold=90).to_dict()
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="multiple risk configurations"):
        run_ablation(evidence, tmp_path / "result.json")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(RiskConfig(high_threshold=95).to_dict()), encoding="utf-8")
    report = run_ablation(evidence, tmp_path / "result.json", config_file)
    assert report["baseline_config"]["high_threshold"] == 95
    assert report["config_source"] == "explicit configuration file"


@pytest.mark.parametrize("payload", [
    {}, {"events": []}, {"events": [None]},
    {"events": [{"timestamp": 1, "path": "x"}]},
    {"events": [{"timestamp": True, "path": "x", "operation": "modified"}]},
    {"events": [{"timestamp": 1, "path": 42, "operation": "modified"}]},
    {"events": [{"timestamp": 1, "path": "x", "operation": "modified", "entropy_before": 9}]},
    {"events": [{"timestamp": 1, "path": "x", "operation": "modified", "process_context": []}]},
])
def test_invalid_exports_fail_before_creating_a_report(tmp_path, payload):
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    target = tmp_path / "result.json"
    with pytest.raises(ValueError):
        run_ablation(evidence, target)
    assert not target.exists()


def test_nonfinite_input_and_overwriting_input_are_rejected(tmp_path):
    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"events": [{"timestamp": NaN, "path":"x", "operation":"modified"}]}', encoding="utf-8")
    with pytest.raises(ValueError, match="Non-finite"):
        run_ablation(evidence, tmp_path / "result.json")
    with pytest.raises(ValueError, match="different"):
        run_ablation(evidence, evidence)


def test_cli_runs_on_actual_sqlite_export_and_reports_failure_exit_status(tmp_path):
    evidence = export_fixture(tmp_path)
    target = tmp_path / "result.json"
    result = subprocess.run([sys.executable, "-m", "scripts.ablation", str(evidence), "--output", str(target)],
                            capture_output=True, text=True, encoding="utf-8", timeout=15)
    assert result.returncode == 0, result.stderr
    assert "16 observations across 6 policies" in result.stdout
    assert json.loads(target.read_text(encoding="utf-8"))["event_count"] == 16
    failure = subprocess.run([sys.executable, "-m", "scripts.ablation", str(evidence), "--output", str(evidence)],
                             capture_output=True, text=True, encoding="utf-8", timeout=15)
    assert failure.returncode == 1
    assert "Output must be different" in failure.stderr


def test_replay_order_and_missing_legacy_configuration_are_explicit(tmp_path):
    evidence = export_fixture(tmp_path)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    for row in payload["events"]:
        row["assessment"].pop("config")
    payload["events"].reverse()
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    report = run_ablation(evidence, tmp_path / "result.json")
    assert report["input_reordered_by_timestamp"] is True
    assert "no configuration was recorded" in report["config_source"]


def test_new_episode_after_idle_window_counts_a_second_crossing(tmp_path):
    evidence = export_fixture(tmp_path)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    repeated = [{**row, "timestamp": row["timestamp"] + 30} for row in payload["events"]]
    payload["events"].extend(repeated)
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    report = run_ablation(evidence, tmp_path / "result.json")
    assert report["variants"]["baseline"]["high_risk_crossings"] == 2
