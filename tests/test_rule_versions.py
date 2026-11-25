"""M3B Step 0: detection-rule versioning keeps the Milestone 3 baseline intact.

No experimental rule is implemented yet. These tests pin backward-compatible
serialization, settings migration, the rule-switch mechanism, and exact
reproduction of every score recorded in the committed M3 pilot.
"""
from __future__ import annotations

from dataclasses import replace
import glob
import json
import os
from pathlib import Path
from types import MappingProxyType

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from ciphersentry import engine as engine_module
from ciphersentry.engine import (
    EXPERIMENTAL_RULES, RULE_VERSIONS, RULES_BASELINE, RULES_EXPERIMENTAL, FileEvent, RiskConfig, RiskEngine,
)
from scripts import eval_workloads as w

REPO = Path(__file__).resolve().parent.parent
PILOT = REPO / "docs" / "validation" / "evaluation-pilot-windows-20261118"
# SHA-256 of the M3 pilot's policy, as recorded in its manifest and summary.
M3_POLICY_SHA256 = "dce51df451e15491ee075618bfe0c09c9268f8f8343686ce9102477f85d6bc97"
LEGACY = {
    "window_seconds": 10.0,
    "uncertain_threshold": 40,
    "high_threshold": 75,
    "weights": {"frequency": 30, "entropy": 35, "operations": 25, "spread": 10, "context": 0},
    "enabled_indicators": ["frequency", "entropy", "operations", "spread", "context"],
}
V2 = RiskConfig(rules_version=RULES_EXPERIMENTAL)


# --- serialization and the M3 fingerprint ----------------------------------

def test_default_rules_are_m3_v1_and_serialize_exactly_as_in_milestone_3():
    config = RiskConfig()
    assert config.rules_version == RULES_BASELINE == "m3-v1"
    assert config.experimental_rules == ()
    assert config.to_dict() == LEGACY
    assert list(config.to_dict()) == list(LEGACY)  # no added keys, same order
    assert w.policy_sha256(config.to_dict()) == M3_POLICY_SHA256
    assert w.policy_sha256(w.FROZEN_POLICY) == M3_POLICY_SHA256


def test_committed_m3_pilot_fingerprint_remains_valid():
    manifest = json.loads((PILOT / "manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((PILOT / "summary.json").read_text(encoding="utf-8"))
    assert manifest["frozen_policy"] == RiskConfig().to_dict() == w.FROZEN_POLICY
    assert manifest["frozen_policy_sha256"] == summary["frozen_policy_sha256"] == M3_POLICY_SHA256
    assert RiskConfig.from_dict(manifest["frozen_policy"]) == RiskConfig()
    assert "policy_version" not in manifest  # format 1: implicitly m3-v1


def test_dictionaries_without_rule_fields_migrate_to_m3_v1():
    assert RiskConfig.from_dict(LEGACY) == RiskConfig()
    assert RiskConfig.from_dict({}) == RiskConfig()
    explicit = RiskConfig.from_dict({**LEGACY, "rules_version": "m3-v1", "experimental_rules": []})
    assert explicit == RiskConfig()
    assert explicit.to_dict() == LEGACY  # canonical form omits the baseline version


def test_m3b_v2_round_trips_with_an_explicit_version_and_a_distinct_fingerprint():
    data = V2.to_dict()
    assert data == {**LEGACY, "rules_version": "m3b-v2", "experimental_rules": []}
    assert RiskConfig.from_dict(data) == V2
    assert V2 != RiskConfig()
    assert w.policy_sha256(data) != M3_POLICY_SHA256
    # Weights, thresholds and window are unchanged in m3b-v2.
    assert {k: v for k, v in data.items() if k in LEGACY} == LEGACY


@pytest.mark.parametrize("bad", [
    {"rules_version": "m3-v3"},
    {"rules_version": 1},
    {"rules_version": None},
    {"rules_version": True},
    {"experimental_rules": "replacement_pairing"},
    {"experimental_rules": ["replacement_pairing"]},  # not implemented
    {"rules_version": "m3b-v2", "experimental_rules": ["block_entropy"]},  # not implemented
    {"rules_version": "m3b-v2", "experimental_rules": [1]},
    {"rule_version": "m3b-v2"},  # misspelled field
])
def test_invalid_rule_fields_are_refused(bad):
    with pytest.raises((ValueError, TypeError)):
        RiskConfig.from_dict({**LEGACY, **bad})


def test_registry_lists_both_versions_and_no_implemented_rules_yet():
    assert set(RULE_VERSIONS) == {"m3-v1", "m3b-v2"}
    # Step 0 implements no detection change. Adding a rule must update this test.
    assert dict(EXPERIMENTAL_RULES) == {}
    assert not RiskConfig().uses_rule("anything") and not V2.uses_rule("anything")


def test_rule_switches_are_opt_in_canonical_and_limited_to_m3b_v2(monkeypatch):
    monkeypatch.setattr(engine_module, "EXPERIMENTAL_RULES",
                        MappingProxyType({"rule_b": "demo", "rule_a": "demo"}))
    both = RiskConfig(rules_version=RULES_EXPERIMENTAL, experimental_rules=("rule_b", "rule_a"))
    assert both.experimental_rules == ("rule_a", "rule_b")
    assert both.uses_rule("rule_a") and both.uses_rule("rule_b")
    one = RiskConfig(rules_version=RULES_EXPERIMENTAL, experimental_rules=["rule_a"])
    assert one.uses_rule("rule_a") and not one.uses_rule("rule_b")
    assert both.to_dict()["experimental_rules"] == ["rule_a", "rule_b"]
    assert RiskConfig.from_dict(both.to_dict()) == both
    assert w.policy_sha256(one.to_dict()) != w.policy_sha256(both.to_dict()) != w.policy_sha256(V2.to_dict())
    with pytest.raises(ValueError):
        RiskConfig(experimental_rules=("rule_a",))  # rules need m3b-v2
    with pytest.raises(ValueError):
        RiskConfig(rules_version=RULES_EXPERIMENTAL, experimental_rules=("rule_a", "rule_a"))


def test_ablation_style_replacement_keeps_the_rule_version():
    reduced = replace(V2, enabled_indicators=("frequency", "entropy"))
    assert reduced.rules_version == RULES_EXPERIMENTAL
    assert RiskConfig.from_dict(reduced.to_dict()) == reduced


# --- exact reproduction of the M3 pilot scores -----------------------------

def _replay(record: dict, config: RiskConfig):
    engine = RiskEngine(config=config)
    for observed in record["observed_events"]:
        # Notification times relative to the first workload action; offsets keep
        # the original spacing, which is all the windowed engine uses.
        timestamp = 1_000_000.0 + observed["notification_wall_s"]
        yield observed, engine.ingest(FileEvent(
            timestamp=timestamp, path=observed["path"], operation=observed["operation"],
            entropy_before=observed["entropy_before"], entropy_after=observed["entropy_after"],
            source="folder", observed_at=timestamp))


@pytest.mark.parametrize("config", [RiskConfig(), V2], ids=["m3-v1", "m3b-v2-no-rules"])
def test_replaying_the_m3_pilot_reproduces_every_recorded_score(config):
    records = [json.loads(Path(p).read_text(encoding="utf-8")) for p in sorted(glob.glob(str(PILOT / "runs" / "*.json")))]
    assert len(records) == 32
    events = 0
    for record in records:
        levels = []
        for observed, assessment in _replay(record, config):
            assert (assessment.level, assessment.score) == (observed["level"], observed["score"]), record["run_id"]
            assert assessment.config == config.to_dict()
            levels.append(assessment.level)
            events += 1
        assert ("High" in levels) == (record["max_level"] == "High")
    assert events == 1278


# --- settings persistence and migration through the real Controller -------

@pytest.fixture(scope="module")
def qt_app():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def _write_settings(root: Path, risk_config: dict) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "settings.json").write_text(json.dumps(
        {"schema_version": 2, "response_mode": "alert_only", "risk_config": risk_config}), encoding="utf-8")


def _saved_risk_config(root: Path) -> dict:
    return json.loads((root / "settings.json").read_text(encoding="utf-8"))["risk_config"]


def test_existing_settings_load_as_m3_v1_and_are_saved_unchanged(tmp_path, qt_app):
    from ciphersentry.controller import Controller
    root = tmp_path / "data"
    _write_settings(root, LEGACY)
    controller = Controller(root)
    try:
        assert controller.engine.config == RiskConfig()
        assert controller.settings["risk_config"] == LEGACY
        controller.save_settings(75, False)
        assert _saved_risk_config(root) == LEGACY  # no rule fields written for m3-v1
    finally:
        controller.close()


def test_m3b_v2_settings_survive_a_policy_form_save_and_reopen(tmp_path, qt_app):
    from ciphersentry.controller import Controller
    root = tmp_path / "data"
    _write_settings(root, V2.to_dict())
    controller = Controller(root)
    try:
        assert controller.engine.config == V2
        form = {key: LEGACY[key] for key in ("window_seconds", "uncertain_threshold", "weights", "enabled_indicators")}
        form["high_threshold"] = 75
        controller.save_settings(75, False, risk_config=form)  # what the GUI policy form sends
        assert controller.engine.config.rules_version == RULES_EXPERIMENTAL
        assert _saved_risk_config(root)["rules_version"] == "m3b-v2"
    finally:
        controller.close()
    reopened = Controller(root)
    try:
        assert reopened.engine.config == V2
        assert reopened.settings["response_mode"] == "alert_only"
        reopened.save_settings(75, False, risk_config={**LEGACY, "rules_version": "m3-v1"})  # explicit return to m3-v1
        assert reopened.engine.config == RiskConfig()
        assert _saved_risk_config(root) == LEGACY
    finally:
        reopened.close()


def test_unknown_rule_version_in_settings_falls_back_to_m3_v1_alert_only(tmp_path, qt_app):
    from ciphersentry.controller import Controller
    root = tmp_path / "data"
    _write_settings(root, {**LEGACY, "rules_version": "m9-unknown"})
    controller = Controller(root)
    try:
        assert controller.engine.config == RiskConfig()
        assert controller.settings["response_mode"] == "alert_only"
        warning = controller.store.recent_actions()[0]
        assert warning["action"] == "settings_migration" and "could not be loaded" in warning["detail"]
    finally:
        controller.close()
