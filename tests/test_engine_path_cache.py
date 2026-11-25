"""M4 Step 3A: the bounded _path_parts cache must return exactly what the uncached parser returns.

The cache is a performance measure only. These tests compare the cached function with a
verbatim copy of the pre-cache implementation, check the bound and eviction, and replay
engine and Controller sequences with and without the cache, comparing complete outputs.
"""
from __future__ import annotations

import glob
import json
import os
import random
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import ciphersentry.engine as engine_module
from ciphersentry.engine import (
    PATH_PARTS_CACHE_SIZE, RULES_EXPERIMENTAL, FileEvent, RiskConfig, RiskEngine, _path_parts,
)

PILOT = Path(__file__).resolve().parent.parent / "docs" / "validation" / "evaluation-pilot-windows-20261118"


def reference_path_parts(path: str) -> tuple[str, str, str]:
    """Verbatim copy of the implementation before the cache was added."""
    windows = "\\" in path or (len(path) > 1 and path[1] == ":")
    parsed = (PureWindowsPath if windows else PurePosixPath)(path)
    return (str(parsed).casefold() if windows else str(parsed),
            str(parsed.parent).casefold() if windows else str(parsed.parent), parsed.suffix.casefold())


SAME_NORMALISED = ["C:\\Watched\\Dept-1\\Report.TXT", "c:/watched/dept-1/report.txt", "C:/Watched\\DEPT-1/report.Txt"]
CASES = [
    "C:\\Users\\Analyst\\Report.DOCX",                    # Windows drive path
    "C:/Users/Analyst/report.docx",                       # Windows forward slashes
    "C:\\a/b\\c.TXT",                                     # mixed separators
    "\\\\fileserver\\Share\\Dept\\File.TXT",              # UNC
    "/home/analyst/Report.TXT",                           # POSIX absolute (case preserved)
    "relative/dir/file.txt", "relative\\Dir\\File.TXT",   # relative
    "file.txt", "README", "archive.tar.GZ",               # bare names
    "MiXeD\\CaSe\\Path.ExT", "/MiXeD/CaSe/Path.ExT",      # mixed case
    "C:\\Watched\\dept-1\\", "/home/analyst/dir/", "C:\\",  # trailing separators / root
    "C:\\Watched\\.\\dept\\..\\file.txt", "./a/../b.txt", "../x.enc", ".", "..",  # dot components
    "C:\\Données\\Résumé.TXT", "/home/ユーザー/文書.txt", "C:\\ß\\Straße.TXT",  # Unicode (ß casefolds)
    "", "C:", "C:file.txt", "x",                          # empty and edge inputs
    "C:\\" + "\\".join(f"segment{i:03d}" for i in range(300)) + "\\file.locked",  # long path
    "/" + "/".join(f"segment{i:03d}" for i in range(300)) + "/file.enc",
    *SAME_NORMALISED,
]


def seeded_corpus(count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    roots = ["C:\\", "c:/", "D:\\Data\\", "\\\\srv\\share\\", "/", "/home/user/", "", "./", "..\\", "Z:"]
    parts = ["Docs", "docs", "DÉPT", "dépt", "a b", "x.y", ".", "..", "ünï", "日本", "dept-1", "Dept-1", "ß"]
    suffixes = ["", ".txt", ".TXT", ".docx", ".locked", ".enc", ".tar.gz", "."]
    corpus = []
    for _ in range(count):
        sep = rng.choice(["\\", "/"])
        depth = rng.randrange(0, 6)
        body = sep.join(rng.choice(parts) for _ in range(depth))
        name = rng.choice(["file", "File", "REPORT", "résumé", "n"]) + rng.choice(suffixes)
        corpus.append(rng.choice(roots) + body + (sep if body else "") + name + rng.choice(["", "", sep]))
    return corpus


# --- the cached function ---------------------------------------------------------------

def test_cache_is_a_bounded_typed_lru_cache():
    assert PATH_PARTS_CACHE_SIZE == 4096
    assert _path_parts.cache_parameters() == {"maxsize": PATH_PARTS_CACHE_SIZE, "typed": True}
    assert _path_parts.__wrapped__.__name__ == "_path_parts"


@pytest.mark.parametrize("path", CASES)
def test_deterministic_cases_match_the_original_parser_on_miss_and_hit(path):
    _path_parts.cache_clear()
    expected = reference_path_parts(path)
    first = _path_parts(path)
    info = _path_parts.cache_info()
    second = _path_parts(path)
    assert first == second == expected == _path_parts.__wrapped__(path)
    assert isinstance(first, tuple) and len(first) == 3 and all(type(item) is str for item in first)
    assert (info.misses, info.hits) == (1, 0)
    assert _path_parts.cache_info().hits == 1


def test_seeded_corpus_matches_on_repeated_and_shuffled_calls():
    corpus = seeded_corpus(3000, 20261124)
    _path_parts.cache_clear()
    expected = [reference_path_parts(p) for p in corpus]
    assert [_path_parts(p) for p in corpus] == expected
    order = list(range(len(corpus)))
    random.Random(7).shuffle(order)
    assert all(_path_parts(corpus[i]) == expected[i] for i in order)
    assert _path_parts.cache_info().hits >= len(corpus)


def test_distinct_strings_with_equal_normalised_values_are_separate_keys():
    _path_parts.cache_clear()
    for path in SAME_NORMALISED + list(reversed(SAME_NORMALISED)) + SAME_NORMALISED:
        assert _path_parts(path) == reference_path_parts(path)
    assert len({_path_parts(p) for p in SAME_NORMALISED}) == 1  # same normalised result...
    assert _path_parts.cache_info().misses == len(SAME_NORMALISED)  # ...but one entry per exact string
    # Interleaving unrelated strings never changes another string's result.
    for path in CASES + SAME_NORMALISED:
        assert _path_parts(path) == reference_path_parts(path)


def test_eviction_keeps_outputs_exact_and_size_bounded():
    _path_parts.cache_clear()
    paths = [f"C:\\Watched\\dept-{i % 50}\\file-{i:06d}.TXT" for i in range(PATH_PARTS_CACHE_SIZE + 1500)]
    for path in paths:
        assert _path_parts(path) == reference_path_parts(path)
    info = _path_parts.cache_info()
    assert info.currsize == PATH_PARTS_CACHE_SIZE == info.maxsize
    assert info.misses == len(paths)
    for path in paths[:200]:  # least recently used, so evicted; recomputed exactly
        assert _path_parts(path) == reference_path_parts(path)
    assert _path_parts.cache_info().misses == len(paths) + 200
    assert _path_parts.cache_info().currsize == PATH_PARTS_CACHE_SIZE


# --- engine and Controller behaviour with and without the cache ---------------------------

def _event(ts, path, op="modified", before=3.0, after=7.9, source="folder", pid=None, start=None):
    if start is not None:
        return FileEvent(timestamp=ts, path=path, operation=op, pid=pid, entropy_before=before, entropy_after=after,
                         source="lab", attribution="cooperative_lab", observed_at=ts,
                         process_context={"pid": pid, "identity_verified": True, "create_time": start})
    return FileEvent(timestamp=ts, path=path, operation=op, entropy_before=before, entropy_after=after,
                     source=source, observed_at=ts)


PATHS = ["C:\\Watched\\dept-0\\a.txt", "C:\\Watched\\dept-1\\B.TXT", "c:/watched/dept-1/b.txt",
         "C:\\Watched\\dept-2\\c.docx.locked", "\\\\server\\share\\dept-3\\d.xlsx", "/home/u/w/dept-4/e.txt",
         "relative\\dept-5\\f.enc", "C:\\Watched\\dépt-7\\h.txt"]


def _scenario():
    ops = [("ingest", _event(1000.0 + 0.5 * i, PATHS[i % 4])) for i in range(8)]
    ops += [("latest", 1010.0), ("ingest", _event(1010.0, PATHS[4])), ("ingest", _event(1009.999999, PATHS[5])),
            ("ingest", _event(1010.000001, PATHS[6])), ("latest", 1010.5), ("latest", 1010.5000001)]
    ops += [("ingest", _event(t, PATHS[k % 8], before=2.0 + k * .3, after=5.0 + k * .4))
            for k, t in enumerate([1011, 1016, 1013, 1019, 1012])]
    ops += [("ingest", _event(1005.0, PATHS[7])), ("ingest", _event(1009.0, PATHS[1])), ("latest", 1020.0)]
    ops += [("ingest", _event(1020 + i * .01, f"C:\\W\\p{i % 7}\\f{i}.txt", pid=5000 + i, start=100.0 + i))
            for i in range(131)]
    ops += [("ingest", _event(1021.0 + i * .2, PATHS[i % 8], source="lab" if i % 3 == 0 else "folder"))
            for i in range(9)]
    ops += [("forget", 5003), ("latest", 1023.0), ("configure", RiskConfig(rules_version=RULES_EXPERIMENTAL)),
            *[("ingest", _event(1030 + i * .3, PATHS[i % 8], op="moved" if i % 4 == 0 else "modified")) for i in range(12)],
            ("latest", 1034.0), ("reset",), ("ingest", _event(1100.0, PATHS[0], op="deleted"))]
    for second in range(30):  # periodic latest() calls across idle gaps longer than the window
        ops += [("ingest", _event(1200 + second + j * .31, PATHS[(second + j) % 8])) for j in range(3 if second % 13 < 6 else 0)]
        ops.append(("latest", 1200 + second + .99))
    return ops


def _run(ops, config):
    engine = RiskEngine(config=config)
    outputs = []
    for op in ops:
        if op[0] == "ingest":
            outputs.append(engine.ingest(op[1]).to_dict())
        elif op[0] == "latest":
            outputs.append([a.to_dict() for a in engine.latest(now=op[1])])
        elif op[0] == "configure":
            engine.configure(op[1])
        elif op[0] == "reset":
            engine.reset()
        elif op[0] == "forget":
            engine.forget_process(op[1])
        outputs.append((engine._watermark, engine.expired_observations,
                        {k: [(e.timestamp, e.path) for e in h] for k, h in engine._history.items()}))
    return outputs


@pytest.mark.parametrize("config", [RiskConfig(), RiskConfig(rules_version=RULES_EXPERIMENTAL)], ids=["m3-v1", "m3b-v2"])
def test_engine_sequences_are_identical_with_and_without_the_cache(config, monkeypatch):
    ops = _scenario()
    _path_parts.cache_clear()
    cached = _run(ops, config)
    assert _path_parts.cache_info().hits > 0
    monkeypatch.setattr(engine_module, "_path_parts", reference_path_parts)
    uncached = _run(ops, config)
    assert cached == uncached


@pytest.mark.parametrize("config", [RiskConfig(), RiskConfig(rules_version=RULES_EXPERIMENTAL)], ids=["m3-v1", "m3b-v2"])
def test_frozen_m3_pilot_full_assessments_are_identical_with_and_without_the_cache(config, monkeypatch):
    records = [json.loads(Path(p).read_text(encoding="utf-8")) for p in sorted(glob.glob(str(PILOT / "runs" / "*.json")))]

    def replay():
        dicts = []
        for record in records:
            engine = RiskEngine(config=config)
            for observed in record["observed_events"]:
                ts = 1_000_000.0 + observed["notification_wall_s"]
                dicts.append(engine.ingest(FileEvent(
                    timestamp=ts, path=observed["path"], operation=observed["operation"],
                    entropy_before=observed["entropy_before"], entropy_after=observed["entropy_after"],
                    source="folder", observed_at=ts)).to_dict())
                dicts.append([a.to_dict() for a in engine.latest(now=ts + .05)])
        return dicts

    _path_parts.cache_clear()
    cached = replay()
    monkeypatch.setattr(engine_module, "_path_parts", reference_path_parts)
    assert cached == replay()
    assert len(cached) == 2 * 1278


def test_controller_alerts_and_current_assessment_are_identical_with_and_without_the_cache(tmp_path, monkeypatch):
    from PySide6.QtWidgets import QApplication
    from ciphersentry.controller import Controller
    QApplication.instance() or QApplication([])
    events = [_event(2000.0 + i * .25, PATHS[i % 8], before=3.0, after=7.9 if i % 5 else 4.0) for i in range(60)]
    events.append(_event(2004.0, PATHS[2]))  # older than the clock minus the window: stored Unscored
    events += [_event(2030.0 + i * .3, PATHS[i % 4]) for i in range(20)]
    clock = {"now": 0.0}
    monkeypatch.setattr(engine_module.time, "time", lambda: clock["now"])

    def run(root):
        controller = Controller(root)
        trace = []
        try:
            for i, event in enumerate(events):
                clock["now"] = event.timestamp + .2
                controller._ingest(event)
                if i % 6 == 5:
                    clock["now"] += .3
                    controller._tick()
                trace.append((controller.assessment.to_dict() if controller.assessment else None,
                              controller.current_response, dict(controller._alert_levels), controller.late_observations))
            con = controller.store._connection
            tables = {t: [dict(r) for r in con.execute(f"SELECT * FROM {t} ORDER BY id")] for t in ("events", "alerts", "actions")}
        finally:
            controller.close()
        return trace, tables

    _path_parts.cache_clear()
    cached = run(tmp_path / "cached")
    monkeypatch.setattr(engine_module, "_path_parts", reference_path_parts)
    uncached = run(tmp_path / "uncached")
    assert cached == uncached
    assert cached[1]["alerts"], "the sequence must exercise alert generation"
    assert any(late for *_, late in cached[0]), "the sequence must include an Unscored late observation"
