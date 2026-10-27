import math
import unittest

from ciphersentry.engine import FileEvent, RiskEngine, shannon_entropy


class RiskEngineTests(unittest.TestCase):
    def make_event(self, index=0, *, source="lab", before=3.0, after=7.9, pid=321, operation="modified"):
        return FileEvent(
            timestamp=1000.0 + index * 0.1,
            path=f"C:\\Demo\\folder{index % 3}\\file{index}.txt",
            operation=operation,
            pid=pid,
            process_name="CipherSentry lab",
            entropy_before=before,
            entropy_after=after,
            source=source,
        )

    def test_entropy_empty_constant_and_uniform(self):
        self.assertEqual(shannon_entropy(b""), 0)
        self.assertEqual(shannon_entropy(b"a" * 1024), 0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256)) * 4), 8)

    def test_combined_evidence_is_explainable_and_eligible(self):
        engine = RiskEngine()
        for index in range(8):
            result = engine.ingest(self.make_event(index))
        self.assertEqual(result.score, 78)
        self.assertEqual(result.level, "High")
        self.assertTrue(result.eligible_for_containment)
        self.assertEqual(result.pid, 321)
        self.assertEqual(result.files_count, 8)
        self.assertEqual(result.directories_count, 3)
        self.assertEqual(sum(signal.points for signal in result.signals), result.score)
        self.assertTrue(all(signal.explanation for signal in result.signals))

    def test_high_io_without_entropy_rises_does_not_trigger(self):
        engine = RiskEngine()
        for index in range(40):
            result = engine.ingest(self.make_event(index, before=3, after=3.2))
        self.assertEqual(result.score, 55)
        self.assertEqual(result.level, "Elevated")
        self.assertFalse(result.eligible_for_containment)

    def test_already_high_entropy_is_not_an_entropy_rise(self):
        engine = RiskEngine()
        for index in range(20):
            result = engine.ingest(self.make_event(index, before=7.8, after=7.9))
        self.assertEqual(next(s.points for s in result.signals if s.name == "Entropy change"), 0)
        self.assertFalse(result.eligible_for_containment)

    def test_missing_baseline_and_single_signal_do_not_trigger(self):
        engine = RiskEngine()
        for index in range(20):
            result = engine.ingest(self.make_event(index, before=None, after=7.9))
        self.assertLess(result.score, 75)
        self.assertFalse(result.eligible_for_containment)
        engine.reset()
        self.assertLess(engine.ingest(self.make_event()).score, 40)

    def test_unattributed_folder_activity_never_becomes_containable(self):
        engine = RiskEngine()
        for index in range(10):
            result = engine.ingest(self.make_event(index, source="folder", pid=999))
        self.assertGreaterEqual(result.score, 75)
        self.assertIsNone(result.pid)
        self.assertFalse(result.eligible_for_containment)
        self.assertIn("Unattributed", result.process_name)

    def test_groups_are_separate_and_old_evidence_expires(self):
        engine = RiskEngine()
        engine.ingest(self.make_event(pid=321))
        engine.ingest(self.make_event(pid=654))
        self.assertEqual(len(engine.latest(now=1001)), 2)
        self.assertEqual(engine.latest(now=1011), [])
        self.assertEqual(engine.latest(now=1012), [])

    def test_window_recomputes_and_out_of_order_events_are_safe(self):
        engine = RiskEngine(window_seconds=1)
        for index in range(8):
            engine.ingest(self.make_event(index))
        self.assertEqual(engine.latest(now=1001.5)[0].files_count, 3)
        old = self.make_event(0)
        result = engine.ingest(old)
        self.assertLess(result.score, 75)
        self.assertEqual(engine.latest(now=1002), [])

    def test_same_file_does_not_inflate_distinct_files_or_entropy(self):
        engine = RiskEngine()
        for _ in range(20):
            result = engine.ingest(self.make_event())
        self.assertEqual(result.files_count, 1)
        self.assertLess(result.score, 40)
        self.assertFalse(result.eligible_for_containment)

    def test_suspicious_renames_are_supporting_evidence(self):
        engine = RiskEngine()
        for index in range(3):
            event = FileEvent(1000 + index, f"/lab/doc{index}.locked", "moved", 321, source="lab")
            result = engine.ingest(event)
        self.assertEqual(next(s.points for s in result.signals if s.name == "Rename pattern"), 15)
        self.assertLess(result.score, 40)

    def test_actual_worker_pattern_exercises_all_five_families(self):
        # Match lab_worker: one combined replacement-and-rename observation per
        # generated text fixture, across four directories, to .locked-demo.
        engine = RiskEngine()
        before = shannon_entropy((b"Disposable CipherSentry research fixture.\n" * 100))
        after = shannon_entropy(bytes(range(256)) * 32)
        results = []
        for index in range(4):
            event = FileEvent(
                timestamp=1000 + index * 0.1,
                path=f"/lab/ciphersentry-run-one/department-{index % 4 + 1}/sample-{index:04d}.locked-demo",
                operation="moved", pid=321, process_name="CipherSentry lab worker",
                entropy_before=before, entropy_after=after, source="lab",
            )
            results.append(engine.ingest(event))
        self.assertTrue(all(not result.eligible_for_containment for result in results[:3]))
        self.assertEqual(results[-1].score, 76)
        self.assertEqual(results[-1].level, "High")
        self.assertTrue(results[-1].eligible_for_containment)
        self.assertTrue(all(signal.points > 0 for signal in results[-1].signals))

    def test_reused_pid_starts_fresh_without_losing_folder_evidence(self):
        engine = RiskEngine()
        for index in range(8):
            engine.ingest(self.make_event(index, pid=321))
        engine.ingest(self.make_event(source="folder"))
        engine.forget_process(321)
        self.assertEqual([result.key for result in engine.latest(now=1001)], ["folder:unattributed"])
        result = engine.ingest(self.make_event(pid=321))
        self.assertEqual(result.files_count, 1)
        self.assertEqual(result.event_count, 1)
        self.assertFalse(result.eligible_for_containment)
        engine.forget_process(987654)  # Repeated cleanup of an unknown PID is safe.

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

    def test_input_validation_and_threshold_updates(self):
        for invalid in [0, -1, math.inf, math.nan]:
            with self.assertRaises(ValueError):
                RiskEngine(window_seconds=invalid)
        for invalid in [39, 101, True, 75.5]:
            with self.assertRaises(ValueError):
                RiskEngine(containment_threshold=invalid)
        engine = RiskEngine(containment_threshold=90)
        for index in range(8):
            result = engine.ingest(self.make_event(index))
        self.assertFalse(result.eligible_for_containment)
        engine.containment_threshold = 75
        self.assertTrue(engine.latest(now=1001)[0].eligible_for_containment)


if __name__ == "__main__":
    unittest.main()
