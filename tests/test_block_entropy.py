"""M3B Step 1: block-level entropy evidence is measured correctly and never scored."""
from __future__ import annotations

from dataclasses import replace
import glob
import json
import os
import random
import threading
import time
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from ciphersentry import block_entropy as be
from ciphersentry.block_entropy import BLOCK_SIZE, BlockEvidence, block_evidence, measure_blocks, measure_sample
from ciphersentry.engine import FileEvent, RiskConfig, RiskEngine, RULES_EXPERIMENTAL, shannon_entropy
from ciphersentry.monitor import FolderMonitor, _Sample, _same_state
from ciphersentry.storage import EventStore
from scripts import ablation

REPO = Path(__file__).resolve().parent.parent
PILOT = REPO / "docs" / "validation" / "evaluation-pilot-windows-20261118"
LEGACY_EVENT_KEYS = ["timestamp", "path", "operation", "pid", "process_name", "entropy_before", "entropy_after",
                     "source", "process_context", "attribution", "observed_at"]


def _random_bytes(size: int, seed: int = 7) -> bytes:
    return random.Random(seed).randbytes(size)


def _text_like(size: int) -> bytes:
    """Deterministic low-entropy document-like content."""
    line = b"Quarterly report: revenue, costs and notes for the review meeting.\r\n"
    return (line * (size // len(line) + 1))[:size]


def _evidence(before: bytes | None, after: bytes | None, operation: str = "modified") -> BlockEvidence:
    return block_evidence(measure_blocks(before, len(before)) if before is not None else None,
                          measure_blocks(after, len(after)) if after is not None else None, operation)


# --- measurement --------------------------------------------------------------

def test_known_low_and_high_entropy_blocks():
    data = bytes(BLOCK_SIZE) + bytes(range(256)) * 16 + b"AB" * 2048 + _random_bytes(BLOCK_SIZE)
    sample = measure_blocks(data, len(data))
    values = sample.entropies()
    assert values[:3] == [0.0, 8.0, 1.0]  # constant, uniform, two equally likely symbols
    assert 7.9 < values[3] <= 8.0         # pseudo-random bytes
    assert sample.lengths() == [BLOCK_SIZE] * 4 and sample.block_count == 4 and not sample.short_read


def test_block_entropy_matches_the_whole_sample_formula_for_each_block():
    data = _text_like(3 * BLOCK_SIZE)
    sample = measure_blocks(data, len(data))
    for index, value in enumerate(sample.entropies()):
        block = data[index * BLOCK_SIZE:(index + 1) * BLOCK_SIZE]
        assert value == round(shannon_entropy(block), 3)


def test_one_pass_whole_sample_entropy_is_bit_identical_to_the_original_function():
    """The monitor's whole-sample value (scored by m3-v1) must not change at all."""
    rng = random.Random(1278)
    cases = [b"", b"x", bytes(BLOCK_SIZE), bytes(range(256)) * 256, _text_like(65536), _random_bytes(65536)]
    for _ in range(400):
        size = rng.choice([rng.randrange(1, 300), rng.randrange(1, 65537), BLOCK_SIZE * rng.randrange(1, 17)])
        alphabet = rng.choice([2, 3, 17, 64, 200, 256])
        skew = rng.random() * 4
        weights = [1 / (index + 1) ** skew for index in range(alphabet)]
        symbols = rng.sample(range(256), alphabet)
        cases.append(bytes(rng.choices(symbols, weights, k=size)))
    for data in cases:
        whole, sample = measure_sample(data, len(data))
        assert whole == shannon_entropy(data)  # exact equality, not approximate
        assert sample == measure_blocks(data, len(data))


def test_measurements_are_deterministic():
    data = _text_like(40_000) + _random_bytes(9_000)
    first, second = measure_blocks(data, len(data)), measure_blocks(bytes(data), len(data))
    assert first == second and first.digests() == second.digests()
    assert _evidence(data, data).to_dict() == _evidence(data, data).to_dict()


def test_partial_overwrite_of_one_block_is_localised():
    before = _text_like(16 * BLOCK_SIZE)
    after = bytearray(before)
    after[5 * BLOCK_SIZE:6 * BLOCK_SIZE] = _random_bytes(BLOCK_SIZE)
    after = bytes(after)
    evidence = _evidence(before, after).to_dict()
    assert evidence["blocks"] == ["unchanged"] * 5 + ["changed"] + ["unchanged"] * 10
    assert evidence["summary"]["changed"] == 1 and evidence["summary"]["unchanged"] == 15
    rise = evidence["after"]["entropy"][5] - evidence["before"]["entropy"][5]
    assert rise > 3 and evidence["summary"]["max_rise"] == round(rise, 3)
    # The whole-sample value barely moves: it would not meet the m3-v1 rise rule.
    whole_rise = shannon_entropy(after) - shannon_entropy(before)
    assert whole_rise < 1.0 and shannon_entropy(after) < 7.0


def test_unchanged_blocks_and_same_entropy_rewrites():
    data = _text_like(3 * BLOCK_SIZE)
    assert _evidence(data, data).to_dict()["blocks"] == ["unchanged"] * 3
    # Reversing a block keeps its byte counts (same entropy) but changes content.
    after = data[:BLOCK_SIZE] + data[BLOCK_SIZE:2 * BLOCK_SIZE][::-1] + data[2 * BLOCK_SIZE:]
    evidence = _evidence(data, after).to_dict()
    assert evidence["blocks"] == ["unchanged", "changed", "unchanged"]
    assert evidence["summary"]["max_rise"] == 0.0


def test_short_files_partial_final_blocks_growth_and_shrinkage():
    short = _text_like(5_000)
    sample = measure_blocks(short, len(short))
    assert sample.lengths() == [BLOCK_SIZE, 904]
    grown = short + _random_bytes(4_000)
    assert _evidence(short, grown).to_dict()["blocks"] == ["unchanged", "length_changed", "after_only"]
    assert _evidence(grown, short).to_dict()["blocks"] == ["unchanged", "length_changed", "before_only"]
    one = measure_blocks(b"x", 1)
    assert one.entropies() == [0.0] and one.lengths() == [1]


def test_empty_file_has_no_blocks_rather_than_invented_values():
    evidence = _evidence(b"", b"").to_dict()
    assert evidence["before"]["entropy"] == [] and evidence["after"]["entropy"] == []
    assert evidence["blocks"] == [] and evidence["summary"]["max_rise"] is None
    assert sum(evidence["summary"][name] for name in be.STATUSES) == 0


def test_files_larger_than_the_sample_are_limited_to_sixteen_blocks():
    data = _text_like(be.MAX_SAMPLE_BYTES)
    sample = measure_blocks(data, file_size=10 * 1024 * 1024)
    assert sample.block_count == be.MAX_BLOCKS == 16
    assert sample.to_dict()["file_size"] == 10 * 1024 * 1024 and not sample.short_read
    with pytest.raises(ValueError):
        measure_blocks(data + b"x", len(data) + 1)


def test_short_read_is_flagged_when_the_file_shrank_during_sampling():
    data = _text_like(5_000)
    assert measure_blocks(data, file_size=20_000).short_read
    assert not measure_blocks(data, file_size=5_000).short_read
    assert not measure_blocks(data, file_size=4_000).short_read  # grew after fstat: more bytes, not fewer


@pytest.mark.parametrize("before, after, operation, reasons", [
    (None, b"new", "created", ("not_in_baseline", None)),
    (b"old", None, "deleted", (None, "deleted")),
    (b"old", None, "modified", (None, "unreadable")),
    (None, None, "modified", ("not_in_baseline", "unreadable")),
])
def test_missing_evidence_is_explicit(before, after, operation, reasons):
    evidence = _evidence(before, after, operation).to_dict()
    assert (evidence["before_missing"], evidence["after_missing"]) == reasons
    assert (evidence["before"] is None) == (reasons[0] is not None)
    assert (evidence["after"] is None) == (reasons[1] is not None)
    assert evidence["blocks"] is None and evidence["summary"] is None


# --- serialization and validation --------------------------------------------

def test_evidence_round_trips_through_json_and_file_event():
    before = _text_like(9_000)
    after = before[:4096] + _random_bytes(4096) + before[8192:]
    evidence = _evidence(before, after)
    data = json.loads(json.dumps(evidence.to_dict()))
    assert BlockEvidence.from_dict(data) == evidence
    event = FileEvent(1.0, "a.txt", "modified", block_entropy=data)
    assert isinstance(event.block_entropy, BlockEvidence)
    assert event.to_dict()["block_entropy"] == evidence.to_dict()
    assert list(event.to_dict()) == LEGACY_EVENT_KEYS + ["block_entropy"]


def test_events_without_block_evidence_serialize_exactly_as_before():
    event = FileEvent(1.0, "a.txt", "modified", entropy_before=4.0, entropy_after=7.5)
    assert list(event.to_dict()) == LEGACY_EVENT_KEYS
    assert FileEvent(**event.to_dict()) == event


def _valid() -> dict:
    before = _text_like(5_000)
    return _evidence(before, before[:4096] + _random_bytes(904)).to_dict()


def _mutate(path, value):
    def apply(data):
        target = data
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        return data
    return apply


@pytest.mark.parametrize("change", [
    _mutate(("format",), "block-entropy-v9"),
    _mutate(("block_size",), 8192),
    _mutate(("block_size",), True),
    _mutate(("extra",), 1),
    _mutate(("before", "entropy", 0), 8.5),
    _mutate(("before", "entropy", 0), -0.1),
    _mutate(("before", "entropy", 0), float("nan")),
    _mutate(("before", "entropy", 0), True),
    _mutate(("before", "entropy", 0), 4.12345),          # more than three decimals
    _mutate(("before", "entropy"), [4.0]),                # wrong block count
    _mutate(("before", "sample_bytes"), 70_000),          # beyond the 64 KiB sample
    _mutate(("before", "short_read"), True),              # inconsistent with sizes
    _mutate(("before", "file_size"), -1),
    _mutate(("after", "entropy", 1), 9.9),                # impossible for a 904-byte block
    _mutate(("blocks", 0), "changed"),                    # possible with equal entropy, but then the summary is wrong
    _mutate(("blocks", 1), "length_changed"),             # block lengths are equal
    _mutate(("blocks",), ["unchanged", "unchanged"]),     # entropy differs, so block 1 cannot be unchanged
    _mutate(("blocks",), ["unchanged"]),                  # wrong length
    _mutate(("blocks",), None),
    _mutate(("summary", "changed"), 5),
    _mutate(("before_missing",), "not_in_baseline"),      # reason given with a measurement
    _mutate(("after_missing",), "corrupted"),
])
def test_invalid_or_inconsistent_evidence_is_refused(change):
    data = change(_valid())
    with pytest.raises(ValueError):
        BlockEvidence.from_dict(data)
    with pytest.raises(ValueError):
        FileEvent(1.0, "a.txt", "modified", block_entropy=data)


def test_side_missing_without_reason_and_blocks_with_missing_side_are_refused():
    data = _evidence(None, b"new", "created").to_dict()
    with pytest.raises(ValueError):
        BlockEvidence.from_dict({**data, "before_missing": None})
    with pytest.raises(ValueError):
        BlockEvidence.from_dict({**data, "blocks": ["after_only"]})
    with pytest.raises(ValueError):
        FileEvent(1.0, "a.txt", "modified", block_entropy="evidence")


def test_store_export_and_ablation_replay_carry_valid_evidence(tmp_path):
    before = _text_like(9_000)
    evidence = _evidence(before, before[:4096] + _random_bytes(4096) + before[8192:])
    event = FileEvent(time.time(), str(tmp_path / "a.txt"), "modified", entropy_before=4.0, entropy_after=4.5,
                      block_entropy=evidence)
    store = EventStore(tmp_path / "evidence.sqlite3")
    try:
        store.record_event(event, RiskEngine().ingest(event))
        plain = replace(event, block_entropy=None)
        store.record_event(plain, RiskEngine().ingest(plain))
        store.export_json(tmp_path / "export.json")
    finally:
        store.close()
    rows = json.loads((tmp_path / "export.json").read_text(encoding="utf-8"))["events"]
    assert rows[0]["block_entropy"] == evidence.to_dict()
    assert "block_entropy" not in rows[1]
    loaded = [ablation._event_from_row(row, index) for index, row in enumerate(rows, 1)]
    assert loaded[0].block_entropy == evidence and loaded[1].block_entropy is None
    rows[0]["block_entropy"]["summary"]["changed"] = 9
    with pytest.raises(ValueError, match="Event 1"):
        ablation._event_from_row(rows[0], 1)


# --- the real monitor ---------------------------------------------------------

HEALTHY_AGE = 0.2   # older than the 60 ms debounce, well below the 2 s overload criterion
BACKLOG_AGE = 5.0   # a notification that has waited 5 s: the monitor is backlogged


def _deliver_many(monitor: FolderMonitor, items: list[tuple], expected: int) -> list[FileEvent]:
    """Run the monitor's consumer on queued notifications (no observer).

    Each item is (operation, path, age_seconds[, destination]). The age is how
    long the notification has already waited, which is the overload criterion.
    """
    events = []
    monitor.callback = events.append
    monitor._stop.clear()
    now = time.time()
    for operation, path, age, *rest in items:
        monitor._pending.put_nowait((operation, str(path), str(rest[0]) if rest else "", now - age))
    consumer = threading.Thread(target=monitor._consume)
    consumer.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and (len(events) < expected or monitor._pending.qsize()):
        time.sleep(0.01)
    time.sleep(0.05)
    monitor._stop.set()
    consumer.join(timeout=2)
    return events


def _deliver(monitor: FolderMonitor, operation: str, path: Path, destination: Path | None = None,
             age: float = HEALTHY_AGE) -> FileEvent | None:
    """Run the monitor's consumer on one queued notification."""
    item = (operation, path, age, destination) if destination else (operation, path, age)
    events = _deliver_many(monitor, [item], 1)
    return events[0] if events else None


def test_monitor_records_a_localised_change_against_its_baseline(tmp_path):
    root = tmp_path.resolve()
    path = root / "report.txt"
    path.write_bytes(_text_like(16 * BLOCK_SIZE))
    monitor = FolderMonitor(root, lambda event: None)
    monitor._build_baseline()
    data = bytearray(path.read_bytes())
    data[5 * BLOCK_SIZE:6 * BLOCK_SIZE] = _random_bytes(BLOCK_SIZE)
    path.write_bytes(bytes(data))
    event = _deliver(monitor, "modified", path)
    assert event is not None
    evidence = event.block_entropy.to_dict()
    assert evidence["blocks"] == ["unchanged"] * 5 + ["changed"] + ["unchanged"] * 10
    assert evidence["after"]["entropy"][5] > 7.9
    # Whole-sample values are exactly what the pre-Step-1 code computed.
    assert event.entropy_before == shannon_entropy(_text_like(16 * BLOCK_SIZE))
    assert event.entropy_after == shannon_entropy(bytes(data))


def test_monitor_new_deleted_and_unreadable_files_name_the_missing_side(tmp_path):
    root = tmp_path.resolve()
    kept, gone = root / "kept.txt", root / "gone.txt"
    kept.write_bytes(_text_like(6_000))
    gone.write_bytes(_text_like(6_000))
    monitor = FolderMonitor(root, lambda event: None)
    monitor._build_baseline()
    new = root / "new.txt"
    new.write_bytes(_random_bytes(5_000))
    created = _deliver(monitor, "created", new).block_entropy.to_dict()
    assert created["before_missing"] == "not_in_baseline" and created["after"]["sample_bytes"] == 5_000
    gone.unlink()
    deleted = _deliver(monitor, "deleted", gone).block_entropy.to_dict()
    assert deleted["after_missing"] == "deleted" and deleted["before"]["sample_bytes"] == 6_000
    kept.write_bytes(_random_bytes(6_000))
    with mock.patch.object(monitor, "_sample", return_value=None):
        unreadable = _deliver(monitor, "modified", kept)
    assert unreadable.block_entropy.to_dict()["after_missing"] == "unreadable"
    assert unreadable.entropy_after is None


def test_inaccessible_read_returns_no_sample_and_reports_it(tmp_path):
    root = tmp_path.resolve()
    path = root / "locked.txt"
    path.write_bytes(b"content")
    errors = []
    monitor = FolderMonitor(root, lambda event: None, errors.append)
    with mock.patch("ciphersentry.monitor.os.read", side_effect=PermissionError(13, "Permission denied")):
        assert monitor._sample(path) is None
    assert errors and "Permission denied" in errors[0]


def test_collection_can_be_switched_off_and_blocks_never_change_deduplication(tmp_path):
    root = tmp_path.resolve()
    path = root / "a.txt"
    path.write_bytes(_text_like(5_000))
    monitor = FolderMonitor(root, lambda event: None)
    monitor.COLLECT_BLOCK_ENTROPY = False
    monitor._build_baseline()
    path.write_bytes(_random_bytes(5_000))
    event = _deliver(monitor, "modified", path)
    assert event.block_entropy is None and list(event.to_dict()) == LEGACY_EVENT_KEYS
    blocks_a = measure_blocks(b"a" * 10, 10)
    blocks_b = measure_blocks(b"b" * 10, 10)
    assert _same_state(_Sample(1.0, 10, 5, blocks_a), _Sample(1.0, 10, 5, blocks_b))
    assert _same_state(_Sample(1.0, 10, 5, None), (1.0, 10, 5))
    assert not _same_state(_Sample(1.0, 10, 5), None) and _same_state(None, None)


# --- adaptive collection under monitoring overload ----------------------------

def _partial_overwrite(path: Path, size: int = 16_384, seed: int = 11) -> bytes:
    """S07-style change: the first 4 KiB of a text document becomes pseudorandom."""
    data = _random_bytes(BLOCK_SIZE, seed) + path.read_bytes()[BLOCK_SIZE:size]
    path.write_bytes(data)
    return data


def test_healthy_monitor_collects_comparable_block_evidence_for_a_partial_overwrite(tmp_path):
    root = tmp_path.resolve()
    path = root / "doc.txt"
    path.write_bytes(_text_like(16_384))
    monitor = FolderMonitor(root, lambda event: None)
    monitor._build_baseline()
    _partial_overwrite(path)
    evidence = _deliver(monitor, "modified", path, age=HEALTHY_AGE).block_entropy.to_dict()
    assert evidence["blocks"] == ["changed", "unchanged", "unchanged", "unchanged"]
    assert evidence["after"]["entropy"][0] > 7.9 and evidence["before_missing"] is evidence["after_missing"] is None
    assert monitor.block_deferred_count == 0


def test_backlogged_monitor_defers_blocks_but_keeps_the_original_whole_sample_entropy(tmp_path):
    root = tmp_path.resolve()
    path = root / "doc.txt"
    original = _text_like(16_384)
    path.write_bytes(original)
    monitor = FolderMonitor(root, lambda event: None)
    monitor._build_baseline()
    changed = _partial_overwrite(path)
    event = _deliver(monitor, "modified", path, age=BACKLOG_AGE)
    evidence = event.block_entropy.to_dict()
    assert evidence["after"] is None and evidence["after_missing"] == "deferred_under_load"
    assert evidence["before"] is not None and evidence["before_missing"] is None
    assert evidence["blocks"] is None and evidence["summary"] is None  # nothing invented
    # Whole-sample values: the same 64 KiB sample and the original calculation.
    assert event.entropy_before == shannon_entropy(original)
    assert event.entropy_after == shannon_entropy(changed)
    assert monitor.block_deferred_count == 1


def test_block_collection_resumes_and_a_deferred_baseline_is_named_not_reused(tmp_path):
    root = tmp_path.resolve()
    a, b = root / "a.txt", root / "b.txt"
    a.write_bytes(_text_like(16_384))
    b.write_bytes(_text_like(16_384))
    monitor = FolderMonitor(root, lambda event: None)
    monitor._build_baseline()
    _partial_overwrite(a, seed=1)
    assert _deliver(monitor, "modified", a, age=BACKLOG_AGE).block_entropy.after_missing == "deferred_under_load"
    _partial_overwrite(b, seed=2)
    resumed = _deliver(monitor, "modified", b).block_entropy.to_dict()
    assert resumed["blocks"] == ["changed", "unchanged", "unchanged", "unchanged"]  # pressure gone: collected
    a.write_bytes(_random_bytes(16_384, 3))
    second = _deliver(monitor, "modified", a).block_entropy.to_dict()
    # a's stored sample has no blocks, so the comparison is missing, not stale.
    assert second["before_missing"] == "deferred_under_load" and second["after"] is not None
    a.write_bytes(_random_bytes(16_384, 4))
    third = _deliver(monitor, "modified", a).block_entropy.to_dict()
    assert third["blocks"] == ["changed"] * 4  # full comparison again
    assert monitor.block_deferred_count == 2  # the first and second events on a


def test_mixed_load_partial_overwrites_during_pressure_are_deferred_and_counted(tmp_path):
    """Controlled mixed load: bulk 64 KiB overwrites and S07-style partial overwrites.

    Notifications that already waited 5 s (backlog) defer block evidence, including
    the partial overwrites among them: 6 of 12 partial overwrites (50%) lose block
    evidence here. This is the accepted limitation; nothing is presented as
    evidence of suspicious activity.
    """
    root = tmp_path.resolve()
    bulk = [root / f"bulk-{i}.bin" for i in range(12)]
    partial = [root / f"doc-{i}.txt" for i in range(12)]
    for path in bulk:
        path.write_bytes(_text_like(be.MAX_SAMPLE_BYTES))
    for path in partial:
        path.write_bytes(_text_like(16_384))
    monitor = FolderMonitor(root, lambda event: None)
    monitor._build_baseline()
    for index, path in enumerate(bulk):
        path.write_bytes(_random_bytes(be.MAX_SAMPLE_BYTES, 100 + index))
    for index, path in enumerate(partial):
        _partial_overwrite(path, seed=200 + index)
    items = []
    for index in range(12):  # backlog: bulk interleaved with the first six partial overwrites
        items.append(("modified", bulk[index], BACKLOG_AGE))
        if index < 6:
            items.append(("modified", partial[index], BACKLOG_AGE))
    items += [("modified", path, HEALTHY_AGE) for path in partial[6:]]  # pressure has passed
    events = {Path(e.path).name: e.block_entropy for e in _deliver_many(monitor, items, len(items))}
    assert len(events) == 24
    assert all(events[p.name].after_missing == "deferred_under_load" for p in bulk + partial[:6])
    for path in partial[6:]:
        assert events[path.name].to_dict()["blocks"] == ["changed", "unchanged", "unchanged", "unchanged"]
    assert monitor.block_deferred_count == 18


def test_deferred_reason_is_validated_and_round_trips():
    text = measure_blocks(_text_like(9_000), 9_000)
    for evidence in (block_evidence(text, None, "modified", after_unmeasured="deferred_under_load"),
                     block_evidence(None, text, "modified", before_unmeasured="deferred_under_load")):
        data = json.loads(json.dumps(evidence.to_dict()))
        assert BlockEvidence.from_dict(data) == evidence
        assert FileEvent(1.0, "a.txt", "modified", block_entropy=data).block_entropy == evidence
        assert data["blocks"] is None and data["summary"] is None
    data = block_evidence(text, None, "modified", after_unmeasured="deferred_under_load").to_dict()
    with pytest.raises(ValueError):
        BlockEvidence.from_dict({**data, "after_missing": "skipped"})


def test_monitor_health_reports_the_deferred_count(tmp_path):
    from PySide6.QtWidgets import QApplication
    from ciphersentry.controller import Controller
    QApplication.instance() or QApplication([])
    controller = Controller(tmp_path / "data")
    try:
        assert controller.monitor_health["block_entropy_deferred"] == 0  # no monitor
        monitor = FolderMonitor(tmp_path.resolve(), lambda event: None)
        monitor._block_deferred = 7
        controller.monitor = monitor
        assert controller.monitor_health["block_entropy_deferred"] == 7
        controller.monitor = type("Double", (), {"baseline_count": 0, "dropped_events": 0, "running": False})()
        assert controller.monitor_health["block_entropy_deferred"] == 0  # monitors without the counter
    finally:
        controller.monitor = None
        controller.close()


# --- no effect on scoring, alerts or response ---------------------------------

def _loud_evidence() -> BlockEvidence:
    """Evidence that every block jumped to high entropy."""
    before = _text_like(be.MAX_SAMPLE_BYTES)
    return _evidence(before, _random_bytes(be.MAX_SAMPLE_BYTES))


def _deferred_evidence() -> BlockEvidence:
    """Evidence whose current side was deferred under load."""
    return block_evidence(measure_blocks(_text_like(be.MAX_SAMPLE_BYTES), be.MAX_SAMPLE_BYTES), None,
                          "modified", after_unmeasured="deferred_under_load")


@pytest.mark.parametrize("make_evidence", [_loud_evidence, _deferred_evidence], ids=["loud", "deferred"])
@pytest.mark.parametrize("config", [RiskConfig(), RiskConfig(rules_version=RULES_EXPERIMENTAL)],
                         ids=["m3-v1", "m3b-v2-no-rules"])
def test_block_evidence_never_changes_assessments(config, make_evidence):
    loud = make_evidence()
    plain_engine, block_engine = RiskEngine(config=config), RiskEngine(config=config)
    for index in range(40):
        event = FileEvent(1000.0 + index * 0.2, f"C:\\lab\\d{index % 4}\\f{index}.txt", "modified",
                          entropy_before=4.0 if index % 3 else None, entropy_after=7.5 if index % 2 else 4.2)
        plain = plain_engine.ingest(event).to_dict()
        with_blocks = block_engine.ingest(replace(event, block_entropy=loud)).to_dict()
        assert with_blocks == plain


def test_replaying_the_m3_pilot_with_block_evidence_attached_reproduces_every_score():
    loud = _loud_evidence()
    records = [json.loads(Path(p).read_text(encoding="utf-8")) for p in sorted(glob.glob(str(PILOT / "runs" / "*.json")))]
    count = 0
    for config in (RiskConfig(), RiskConfig(rules_version=RULES_EXPERIMENTAL)):
        for record in records:
            engine = RiskEngine(config=config)
            for observed in record["observed_events"]:
                timestamp = 1_000_000.0 + observed["notification_wall_s"]
                assessment = engine.ingest(FileEvent(
                    timestamp=timestamp, path=observed["path"], operation=observed["operation"],
                    entropy_before=observed["entropy_before"], entropy_after=observed["entropy_after"],
                    source="folder", observed_at=timestamp, block_entropy=loud))
                assert (assessment.level, assessment.score) == (observed["level"], observed["score"])
                count += 1
    assert count == 2 * 1278


@pytest.mark.parametrize("make_evidence", [_loud_evidence, _deferred_evidence], ids=["loud", "deferred"])
def test_block_evidence_alone_cannot_raise_an_alert_or_response(tmp_path, make_evidence):
    from PySide6.QtWidgets import QApplication
    from ciphersentry.controller import Controller
    QApplication.instance() or QApplication([])
    controller = Controller(tmp_path / "data")
    try:
        loud = make_evidence()
        now = time.time()
        reference = RiskEngine(config=controller.engine.config)
        expected = []
        for index in range(3):  # whole-sample entropy unknown; every block looks encrypted
            event = FileEvent(now + index * 0.1, str(tmp_path / f"f{index}.txt"), "modified")
            expected.append(reference.ingest(event).score)
            controller._ingest(replace(event, block_entropy=loud))
        assert controller.store.recent_alerts() == []
        rows = list(reversed(controller.store.recent_events()))
        assert [row["score"] for row in rows] == expected  # same as without block evidence
        assert {row["level"] for row in rows} == {"Low"}
        assert all(row["block_entropy"] == loud.to_dict() for row in rows)
        assert all(row["response"] is None or not row["response"].get("allowed") for row in rows)
        assert not any(a["action"].startswith("worker_") for a in controller.store.recent_actions())
    finally:
        controller.close()
