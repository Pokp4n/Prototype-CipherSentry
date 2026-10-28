import math
import unittest
from dataclasses import replace

from ciphersentry.engine import DEFAULT_WEIGHTS, INDICATORS, FileEvent, RiskConfig, RiskEngine, shannon_entropy


class RiskEngineTests(unittest.TestCase):
    def make_event(self, index=0, *, source="lab", before=3.0, after=7.9, pid=321,
                   operation="modified", attribution="cooperative_lab", start=900.0):
        return FileEvent(
            timestamp=1000.0 + index * .1,
            path=f"C:\\Demo\\folder{index % 3}\\file{index}.txt", operation=operation,
            pid=pid, process_name="CipherSentry lab", entropy_before=before, entropy_after=after,
            source=source, attribution=attribution,
            process_context={"pid": pid, "create_time": start, "executable": "C:\\Python\\python.exe",
                             "parent_pid": 1, "signature_status": "not_checked"},
        )

    def ingest_many(self, engine, count=8, **kwargs):
        for index in range(count):
            result = engine.ingest(self.make_event(index, **kwargs))
        return result

    def test_entropy_empty_constant_and_uniform(self):
        self.assertEqual(shannon_entropy(b""), 0)
        self.assertEqual(shannon_entropy(b"a" * 1024), 0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256)) * 4), 8)

    def test_combined_evidence_is_explainable_candidate_not_action_authorization(self):
        result = self.ingest_many(RiskEngine())
        self.assertEqual(result.score, 92)
        self.assertEqual(result.level, "High")
        self.assertTrue(result.eligible_for_containment)
        self.assertIn("separate safety review", result.response_reason)
        self.assertEqual(result.pid, 321)
        self.assertEqual(result.files_count, 8)
        self.assertEqual(result.directories_count, 3)
        self.assertEqual(sum(signal.points for signal in result.signals), result.score)
        self.assertEqual([s.name for s in result.signals], ["File modification frequency", "Entropy change",
                         "Repeated operations", "Directory spread", "Process context"])
        self.assertEqual(result.features["process_context"]["create_time"], 900)
        self.assertTrue(all(signal.explanation for signal in result.signals))

    def test_high_io_without_entropy_rises_is_uncertain_and_not_containable(self):
        result = self.ingest_many(RiskEngine(), 40, before=3, after=3.2)
        self.assertEqual(result.score, 65)
        self.assertEqual(result.level, "Uncertain")
        self.assertFalse(result.eligible_for_containment)

    def test_already_high_entropy_is_not_an_entropy_rise(self):
        result = self.ingest_many(RiskEngine(), 20, before=7.8, after=7.9)
        self.assertEqual(next(s.points for s in result.signals if s.name == "Entropy change"), 0)
        self.assertFalse(result.eligible_for_containment)

    def test_missing_entropy_is_explicit_unknown_evidence(self):
        result = self.ingest_many(RiskEngine(), 20, before=None, after=7.9)
        self.assertLess(result.score, 75)
        entropy = next(s for s in result.signals if s.name == "Entropy change")
        self.assertFalse(entropy.available)
        self.assertEqual(entropy.points, 0)
        self.assertTrue(any("entropy" in message for message in result.missing_evidence))
        self.assertIn("unknown", entropy.explanation)

    def test_unattributed_folder_activity_never_becomes_containable(self):
        result = self.ingest_many(RiskEngine(), 10, source="folder", pid=999)
        self.assertGreaterEqual(result.score, 75)
        self.assertIsNone(result.pid)
        self.assertFalse(result.eligible_for_containment)
        self.assertIn("Unattributed", result.process_name)
        self.assertEqual(result.attribution, "unavailable")
        self.assertTrue(any("read calls" in message for message in result.missing_evidence))

    def test_lab_source_and_pid_without_provenance_are_insufficient(self):
        result = self.ingest_many(RiskEngine(), attribution="unavailable")
        self.assertIsNone(result.pid)
        self.assertFalse(result.eligible_for_containment)
        event = replace(self.make_event(), process_context=None)
        self.assertIsNone(RiskEngine().ingest(event).pid)
        event = replace(self.make_event(), process_context={"pid": 999, "create_time": 900})
        self.assertIsNone(RiskEngine().ingest(event).pid)
        event = replace(self.make_event(), process_context={**self.make_event().process_context, "identity_verified": False})
        self.assertIsNone(RiskEngine().ingest(event).pid)

    def test_groups_are_separate_and_old_evidence_expires(self):
        engine = RiskEngine()
        engine.ingest(self.make_event(pid=321))
        engine.ingest(self.make_event(pid=654))
        self.assertEqual(len(engine.latest(now=1001)), 2)
        self.assertEqual(engine.latest(now=1011), [])

    def test_window_recomputes_and_out_of_order_events_are_safe(self):
        engine = RiskEngine(window_seconds=1)
        self.ingest_many(engine)
        self.assertEqual(engine.latest(now=1001.5)[0].files_count, 3)
        result = engine.ingest(self.make_event(0))
        self.assertLess(result.score, 75)
        self.assertEqual(engine.latest(now=1002), [])

    def test_expired_arrival_and_clock_rollback_cannot_revive_old_evidence(self):
        engine = RiskEngine()
        self.ingest_many(engine)
        self.assertEqual(engine.latest(now=1020), [])
        stale = engine.ingest(self.make_event())
        self.assertEqual(stale.event_count, 0)
        self.assertEqual(stale.score, 0)
        self.assertFalse(stale.eligible_for_containment)
        self.assertIn("predates", stale.response_reason)
        self.assertEqual(engine.latest(now=1001), [])
        engine.reset()
        self.assertEqual(engine.ingest(self.make_event()).event_count, 1)

    def test_same_file_separates_modification_rate_from_unique_rate(self):
        engine = RiskEngine()
        for _ in range(20):
            result = engine.ingest(self.make_event())
        self.assertEqual(result.files_count, 1)
        self.assertEqual(result.features["modification_rate"], 2)
        self.assertEqual(result.features["unique_modified_rate"], .1)
        self.assertLess(result.score, 40)
        self.assertFalse(result.eligible_for_containment)

    def test_renames_are_operation_evidence_not_a_fifth_indicator_or_proven_write(self):
        engine = RiskEngine()
        for index in range(8):
            result = engine.ingest(FileEvent(1000 + index * .1, f"/lab/doc{index}.locked", "moved"))
        self.assertEqual(result.features["rename_suffix_files"], 8)
        self.assertEqual(result.features["modification_count"], 0)
        self.assertEqual(result.features["modified_directories"], 0)
        self.assertNotIn("Rename pattern", [s.name for s in result.signals])
        self.assertLess(result.score, 40)

    def test_lab_combined_rewrite_and_rename_is_explicit(self):
        result = self.ingest_many(RiskEngine(), operation="moved")
        self.assertEqual(result.features["combined_lab_rewrites"], 8)
        self.assertEqual(result.features["modification_count"], 8)
        self.assertTrue(result.eligible_for_containment)

    def test_single_directory_can_reach_high_risk(self):
        engine = RiskEngine()
        for index in range(8):
            result = engine.ingest(replace(self.make_event(index), path=f"/one/f{index}.txt"))
        self.assertEqual(result.directories_count, 1)
        self.assertEqual(result.score, 82)
        self.assertTrue(result.eligible_for_containment)
        self.assertEqual(next(s.points for s in result.signals if s.name == "Directory spread"), 0)

    def test_nested_directories_count_immediate_parents_only(self):
        engine = RiskEngine()
        for index, path in enumerate(["C:\\Data\\f.txt", "c:\\data\\child\\a.txt", "C:\\DATA\\CHILD\\b.txt"]):
            result = engine.ingest(replace(self.make_event(index), path=path))
        self.assertEqual(result.directories_count, 2)

    def test_operations_include_read_and_transitions_without_fixed_sequence(self):
        engine = RiskEngine()
        for index, operation in enumerate(["read", "modified", "deleted", "read", "moved"]):
            result = engine.ingest(self.make_event(index, operation=operation))
        self.assertEqual(result.features["operation_counts"]["read"], 2)
        self.assertEqual(result.features["operation_transitions"]["deleted → read"], 1)

    def test_context_is_not_a_name_or_signature_reputation_rule(self):
        for name, signature in [("unknown.exe", "invalid"), ("explorer.exe", "valid")]:
            event = self.make_event()
            context = {**event.process_context, "signature_status": signature}
            result = RiskEngine().ingest(replace(event, process_name=name, process_context=context))
            signal = next(s for s in result.signals if s.name == "Process context")
            self.assertEqual(signal.points, 0)
            self.assertTrue(signal.available)

    def test_partial_process_metadata_errors_are_preserved_as_missing_evidence(self):
        event = self.make_event()
        context = {**event.process_context, "identity_verified": True, "executable": None,
                   "missing": ["executable"], "errors": ["Permission denied for executable."]}
        result = RiskEngine().ingest(replace(event, process_context=context))
        self.assertTrue(any("executable" in message for message in result.missing_evidence))
        self.assertTrue(any("Permission denied" in message for message in result.missing_evidence))

    def test_pid_reuse_is_separate_and_explicit_reset_keeps_folder_evidence(self):
        engine = RiskEngine()
        self.ingest_many(engine)
        result = engine.ingest(self.make_event(start=950))
        self.assertEqual(result.event_count, 1)
        self.assertEqual(len(engine.latest(now=1001)), 2)
        engine.ingest(self.make_event(source="folder"))
        engine.forget_process(321)
        self.assertEqual([result.key for result in engine.latest(now=1001)], ["folder:unattributed"])
        engine.forget_process(987654)

    def test_memory_has_bounds(self):
        engine = RiskEngine()
        engine.MAX_EVENTS_PER_GROUP = 12
        engine.MAX_GROUPS = 2
        for _ in range(20):
            result = engine.ingest(self.make_event(pid=1))
        self.assertEqual(result.event_count, 12)
        engine.ingest(self.make_event(pid=2))
        engine.ingest(self.make_event(pid=3))
        self.assertEqual(len(engine.latest(now=1001)), 2)

    def test_input_validation_and_compatibility_threshold_update(self):
        for invalid in [0, -1, math.inf, math.nan, True]:
            with self.assertRaises(ValueError):
                RiskEngine(window_seconds=invalid)
        for invalid in [39, 101, True, 75.5]:
            with self.assertRaises(ValueError):
                RiskEngine(containment_threshold=invalid)
        engine = RiskEngine(containment_threshold=95)
        result = self.ingest_many(engine)
        self.assertFalse(result.eligible_for_containment)
        engine.containment_threshold = 75
        self.assertTrue(engine.latest(now=1001)[0].eligible_for_containment)
        with self.assertRaises(ValueError):
            engine.ingest(replace(self.make_event(), timestamp=math.nan))

    def test_ablation_excludes_points_without_renormalizing(self):
        full = self.ingest_many(RiskEngine())
        config = RiskConfig(enabled_indicators=["frequency", "operations", "spread", "context"])
        ablated = self.ingest_many(RiskEngine(config=config))
        self.assertEqual(ablated.score, full.score - 35)
        self.assertEqual(ablated.level, "Uncertain")
        self.assertFalse(ablated.eligible_for_containment)
        self.assertIn("Disabled", next(s.explanation for s in ablated.signals if s.name == "Entropy change"))

    def test_single_indicator_default_weight_does_not_reach_high(self):
        for indicator in ["frequency", "entropy"]:
            result = self.ingest_many(RiskEngine(config=RiskConfig(enabled_indicators=[indicator])), 40)
            self.assertLess(result.score, 40)
            self.assertFalse(result.eligible_for_containment)

    def test_high_single_family_score_still_cannot_authorize_containment(self):
        weights = {name: 100 if name == "frequency" else 0 for name in INDICATORS}
        result = self.ingest_many(RiskEngine(config=RiskConfig(weights=weights)), 40)
        self.assertEqual(result.level, "High")
        self.assertFalse(result.eligible_for_containment)
        self.assertIn("fewer than three", result.response_reason)

    def test_configure_resets_window_and_snapshots_configuration(self):
        engine = RiskEngine()
        self.ingest_many(engine)
        config = RiskConfig(window_seconds=20, high_threshold=90)
        engine.configure(config)
        self.assertEqual(engine.latest(now=1001), [])
        result = engine.ingest(self.make_event())
        self.assertEqual(result.config, config.to_dict())


class RiskConfigTests(unittest.TestCase):
    def test_config_round_trip_is_immutable_and_copies_inputs(self):
        weights = DEFAULT_WEIGHTS.copy()
        enabled = list(INDICATORS)
        config = RiskConfig(weights=weights, enabled_indicators=enabled)
        weights["frequency"] = 0
        enabled.clear()
        self.assertEqual(config.weights["frequency"], 30)
        self.assertEqual(config.enabled_indicators, INDICATORS)
        self.assertEqual(RiskConfig.from_dict(config.to_dict()).to_dict(), config.to_dict())
        with self.assertRaises(TypeError):
            config.weights["frequency"] = 1

    def test_invalid_configuration_is_rejected(self):
        invalid = [
            {"unknown": 1}, {"window_seconds": math.nan}, {"window_seconds": True},
            {"window_seconds": 301}, {"uncertain_threshold": 80}, {"high_threshold": True},
            {"high_threshold": 101}, {"weights": {"frequency": 30}},
            {"weights": {**DEFAULT_WEIGHTS, "context": 1}},
            {"weights": {**DEFAULT_WEIGHTS, "frequency": False}},
            {"weights": {**DEFAULT_WEIGHTS, "frequency": -1}},
            {"enabled_indicators": ["frequency", "frequency"]}, {"enabled_indicators": ["unknown"]},
            {"enabled_indicators": "frequency"}, {"enabled_indicators": [1]},
        ]
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                RiskConfig.from_dict(payload)
        with self.assertRaises(ValueError):
            RiskConfig.from_dict([])


if __name__ == "__main__":
    unittest.main()
