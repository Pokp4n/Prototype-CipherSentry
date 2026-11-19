"""Labelled, deterministic file workloads for CipherSentry evaluation.

Every workload is synthetic and harmless: it only touches generated fixture
files inside a fresh, marker-owned directory. "Suspicious" workloads replace
disposable fixture contents with seeded pseudorandom bytes; no encryption,
key handling, discovery, persistence, privilege change or real malware is
involved.

Labels are fixed by each workload's *design* (see ``LABEL_RULE``) before any
run, and never derived from CipherSentry's score.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import random
import sys
import threading
import time
import zipfile

BENIGN = "benign"
SUSPICIOUS = "suspicious"
DEVELOPMENT = "development"
HELDOUT = "heldout"

LABEL_RULE = (
    "A workload is labelled 'suspicious' when its design performs an unauthorized, ransomware-like "
    "impact: it replaces the original contents of at least three pre-existing fixture files with "
    "unrelated high-entropy bytes (in place, partially, or by writing a replacement and deleting the "
    "original) without keeping a recoverable copy. Every other workload is 'benign': it edits, copies, "
    "archives, appends or exports while preserving the user's data, or it is a transformation the "
    "user explicitly authorized. Labels come from this design rule, never from a CipherSentry score."
)

# The detection policy evaluated in Milestone 3 (detection rules m3-v1). The
# harness refuses to run if the live engine configuration differs, so results
# cannot silently mix policies. This dictionary must never change: its SHA-256
# (dce51df4...) identifies the M3 pilot results.
FROZEN_POLICY = {
    "window_seconds": 10.0,
    "uncertain_threshold": 40,
    "high_threshold": 75,
    "weights": {"frequency": 30, "entropy": 35, "operations": 25, "spread": 10, "context": 0},
    "enabled_indicators": ["frequency", "entropy", "operations", "spread", "context"],
}

# Same weights, thresholds and window as M3; only the detection-rule version
# differs. No experimental rule is implemented yet, so it scores like m3-v1.
M3B_V2_POLICY = {**FROZEN_POLICY, "rules_version": "m3b-v2", "experimental_rules": []}

DEFAULT_POLICY_VERSION = "m3-v1"
EVALUATION_POLICIES = {
    "m3-v1": {"policy": FROZEN_POLICY, "status": "frozen",
              "note": "Milestone 3 baseline rules; the policy of the 2026-11-18 pilot."},
    "m3b-v2": {"policy": M3B_V2_POLICY, "status": "experimental",
               "note": "M3B experimental rules; not frozen. Results are development evidence until the "
                       "rules are frozen and evaluated on new held-out workloads."},
}


def evaluation_policy(version: str) -> dict:
    """Return a copy of the named evaluation policy entry; unknown names are refused."""
    if version not in EVALUATION_POLICIES:
        raise ValueError(f"Unknown evaluation policy {version!r}; choose one of: {', '.join(EVALUATION_POLICIES)}")
    entry = EVALUATION_POLICIES[version]
    return {"version": version, "policy": json.loads(json.dumps(entry["policy"])),
            "status": entry["status"], "note": entry["note"]}

MARKER = ".ciphersentry-eval-owned"
MARKER_KIND = "CipherSentry disposable evaluation fixtures"
MAX_FILES = 400
MAX_STEPS = 2000
TEXT_SIZE_TARGET = 4096


def policy_sha256(policy: dict) -> str:
    return hashlib.sha256(json.dumps(policy, sort_keys=True).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WorkloadSpec:
    workload_id: str
    family: str
    label: str
    split: str
    seed: int
    description: str
    label_rationale: str
    params: dict = field(default_factory=dict)
    difficulty_notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --- deterministic content -------------------------------------------------

def text_bytes(index: int, revision: int, size: int = TEXT_SIZE_TARGET) -> bytes:
    """Low-entropy, human-like generated text (no personal data)."""
    line = (f"Disposable evaluation document {index:04d}, revision {revision}. "
            "Quarterly notes, meeting minutes and ordinary prose for testing only.\n")
    repeated = (line * (size // len(line) + 1)).encode("utf-8")
    return repeated[:size]


def random_bytes(seed: int, tag: str, size: int) -> bytes:
    """Seeded pseudorandom bytes: high entropy, reproducible, not ciphertext."""
    return random.Random(f"{seed}:{tag}").randbytes(size)


# --- fixtures and plans ----------------------------------------------------
# A fixture is {"path", "kind", "index", "size"}. A plan is a list of steps;
# each step is a list of actions executed back to back, then "delay" seconds.

def _dirs(count: int, prefix: str = "dept") -> list[str]:
    return [f"{prefix}-{i + 1:02d}" for i in range(count)]


def _text_fixtures(files: int, dirs: int, ext: str = ".txt", size: int = TEXT_SIZE_TARGET) -> list[dict]:
    folders = _dirs(dirs)
    return [{"path": f"{folders[i % dirs]}/doc-{i:04d}{ext}", "kind": "text", "index": i, "size": size}
            for i in range(files)]


def build_fixtures(spec: WorkloadSpec) -> list[dict]:
    p = spec.params
    family = spec.family
    if family in {"doc_edit", "bulk_text_rewrite", "backup_copy", "zip_archive", "authorized_encryption",
                  "overwrite", "replace_and_delete"}:
        return _text_fixtures(p["files"], p["dirs"])
    if family == "partial_overwrite":
        return _text_fixtures(p["files"], p["dirs"], size=p["size"])
    if family == "single_file_autosave":
        return [{"path": "notes/draft.txt", "kind": "text", "index": 0, "size": TEXT_SIZE_TARGET}]
    if family == "log_append":
        return [{"path": f"logs/service-{i}.log", "kind": "text", "index": i, "size": 2048} for i in range(p["logs"])]
    if family == "encrypted_export":
        return _text_fixtures(p["files"], p["dirs"])
    if family == "media_reexport":
        folders = _dirs(p["dirs"], "album")
        return [{"path": f"{folders[i % p['dirs']]}/photo-{i:04d}.jpg", "kind": "random", "index": i, "size": 8192}
                for i in range(p["files"])]
    raise ValueError(f"Unknown workload family: {family}")


def build_plan(spec: WorkloadSpec) -> list[dict]:
    p = spec.params
    rng = random.Random(spec.seed)
    fixtures = build_fixtures(spec)
    paths = [f["path"] for f in fixtures]
    delay = float(p.get("delay", 0.1))
    steps: list[list[dict]] = []
    family = spec.family
    if family == "doc_edit":
        order = [i for _ in range(p["edits"]) for i in range(len(paths))]
        for n, i in enumerate(order):
            steps.append([{"op": "write_text", "path": paths[i], "index": i, "revision": n + 1}])
    elif family == "single_file_autosave":
        steps = [[{"op": "write_text", "path": paths[0], "index": 0, "revision": n + 1}] for n in range(p["saves"])]
    elif family == "bulk_text_rewrite":
        order = list(range(len(paths)))
        rng.shuffle(order)
        steps = [[{"op": "write_text", "path": paths[i], "index": i, "revision": 1}] for i in order]
    elif family == "backup_copy":
        order = list(range(len(paths)))
        rng.shuffle(order)
        steps = [[{"op": "copy", "path": paths[i], "dest": f"backup/{paths[i]}"}] for i in order]
    elif family == "zip_archive":
        order = list(range(len(paths)))
        rng.shuffle(order)
        steps = [[{"op": "zip", "path": paths[i], "dest": str(PurePosixPath(paths[i]).with_suffix(".zip"))}]
                 for i in order]
    elif family == "log_append":
        steps = [[{"op": "append_text", "path": paths[n % len(paths)], "index": n}] for n in range(p["appends"])]
    elif family == "encrypted_export":
        steps = [[{"op": "create_random", "path": f"export/archive-{n:04d}.bin", "tag": f"export-{n}", "size": 8192}]
                 for n in range(p["exports"])]
    elif family == "media_reexport":
        order = list(range(len(paths)))
        rng.shuffle(order)
        steps = [[{"op": "write_random", "path": paths[i], "tag": f"render-{i}", "size": 8192}] for i in order]
    elif family in {"overwrite", "authorized_encryption"}:
        order = list(range(len(paths)))
        rng.shuffle(order)
        suffix = p.get("rename_suffix")
        for i in order:
            step = [{"op": "write_random", "path": paths[i], "tag": f"overwrite-{i}", "size": 8192}]
            if suffix:
                step.append({"op": "rename", "path": paths[i], "dest": str(PurePosixPath(paths[i]).with_suffix(suffix))})
            steps.append(step)
    elif family == "replace_and_delete":
        order = list(range(len(paths)))
        rng.shuffle(order)
        for i in order:
            dest = str(PurePosixPath(paths[i]).with_suffix(p.get("suffix", ".locked")))
            steps.append([{"op": "create_random", "path": dest, "tag": f"replace-{i}", "size": 8192},
                          {"op": "delete", "path": paths[i]}])
    elif family == "partial_overwrite":
        order = list(range(len(paths)))
        rng.shuffle(order)
        steps = [[{"op": "overwrite_prefix", "path": paths[i], "tag": f"prefix-{i}", "size": p["prefix"]}]
                 for i in order]
    else:
        raise ValueError(f"Unknown workload family: {family}")
    if len(steps) > MAX_STEPS:
        raise ValueError("Plan exceeds the step limit")
    return [{"step": n, "delay": delay, "actions": actions} for n, actions in enumerate(steps)]


def expected_observations(plan: list[dict]) -> list[dict]:
    """Paths and operations a path-notification collector should report."""
    expected = []
    for step in plan:
        for action in step["actions"]:
            op = action["op"]
            if op in {"write_text", "write_random", "append_text", "overwrite_prefix"}:
                expected.append({"path": action["path"], "operation": "modified"})
            elif op in {"copy", "zip"}:
                expected.append({"path": action["dest"], "operation": "created"})
            elif op == "create_random":
                expected.append({"path": action["path"], "operation": "created"})
            elif op == "rename":
                expected.append({"path": action["dest"], "operation": "moved"})
            elif op == "delete":
                expected.append({"path": action["path"], "operation": "deleted"})
    return expected


# --- catalog ---------------------------------------------------------------
# Development variants exist so the harness can be built and debugged without
# looking at held-out runs. No detection parameter is tuned on either split.

def _spec(workload_id, family, label, split, seed, description, rationale, params, notes=""):
    return WorkloadSpec(workload_id, family, label, split, seed, description, rationale, params, notes)


def catalog() -> list[WorkloadSpec]:
    specs = []

    def pair(base, family, label, description, rationale, dev, held, notes=""):
        specs.append(_spec(f"{base}/dev", family, label, DEVELOPMENT, 1000 + len(specs), description, rationale, dev, notes))
        specs.append(_spec(f"{base}/heldout", family, label, HELDOUT, 2000 + len(specs), description, rationale, held, notes))

    keeps = "Preserves user data; no original content is replaced by unrelated high-entropy bytes."
    pair("B01-document-editing", "doc_edit", BENIGN,
         "A user edits a few text documents in one folder, saving each twice.",
         keeps, {"files": 4, "dirs": 1, "edits": 2, "delay": 0.8},
         {"files": 5, "dirs": 2, "edits": 2, "delay": 0.7})
    pair("B02-repeated-single-file", "single_file_autosave", BENIGN,
         "An editor autosaves one document repeatedly.",
         keeps, {"saves": 20, "delay": 0.3}, {"saves": 30, "delay": 0.2})
    pair("B03-bulk-text-rewrite", "bulk_text_rewrite", BENIGN,
         "A legitimate find-and-replace rewrites many text files across folders with new low-entropy text.",
         keeps, {"files": 40, "dirs": 4, "delay": 0.05}, {"files": 60, "dirs": 5, "delay": 0.04},
         "High activity and spread with low entropy: tests frequency/operations/spread without entropy.")
    pair("B04-backup-copy", "backup_copy", BENIGN,
         "A backup tool copies documents into a mirrored backup tree (originals untouched).",
         keeps, {"files": 40, "dirs": 4, "delay": 0.05}, {"files": 50, "dirs": 5, "delay": 0.04})
    pair("B05-zip-archive", "zip_archive", BENIGN,
         "ZIP archives are created next to each document; originals are kept.",
         keeps, {"files": 30, "dirs": 3, "delay": 0.08}, {"files": 40, "dirs": 4, "delay": 0.06},
         "New high-entropy files without a prior entropy baseline.")
    pair("B06-encrypted-export", "encrypted_export", BENIGN,
         "An application writes new encrypted-looking export files into one folder; sources are untouched.",
         keeps, {"files": 6, "dirs": 1, "exports": 30, "delay": 0.08},
         {"files": 6, "dirs": 1, "exports": 40, "delay": 0.06})
    pair("B07-log-append", "log_append", BENIGN,
         "Services append lines to a few log files at a high rate.",
         keeps, {"logs": 3, "appends": 60, "delay": 0.05}, {"logs": 4, "appends": 80, "delay": 0.04})
    pair("B08-media-reexport", "media_reexport", BENIGN,
         "A photo tool re-renders existing compressed images; contents are high entropy before and after.",
         "Replaces media with newly rendered media of the same kind at the user's request.",
         {"files": 30, "dirs": 3, "delay": 0.06}, {"files": 40, "dirs": 4, "delay": 0.05},
         "Hard benign case: high-volume overwrite of already high-entropy files.")
    pair("B09-authorized-encryption", "authorized_encryption", BENIGN,
         "The user runs an authorized tool that encrypts disposable documents in place.",
         "User-authorized transformation. Its file behaviour is intentionally indistinguishable from S01; "
         "it measures the limit of behaviour-only detection, not a defect to tune away.",
         {"files": 30, "dirs": 3, "delay": 0.08}, {"files": 40, "dirs": 4, "delay": 0.06},
         "Intent-only difference from the suspicious overwrite family; an alert is the expected limitation.")

    unauthorized = "Unauthorized replacement of at least three pre-existing documents with high-entropy bytes."
    pair("S01-rapid-overwrite-multidir", "overwrite", SUSPICIOUS,
         "Rapidly overwrites documents across several folders with pseudorandom bytes.",
         unauthorized, {"files": 40, "dirs": 4, "delay": 0.05}, {"files": 50, "dirs": 5, "delay": 0.04})
    pair("S02-overwrite-and-rename", "overwrite", SUSPICIOUS,
         "Overwrites each document with pseudorandom bytes, then renames it with a .locked suffix.",
         unauthorized, {"files": 30, "dirs": 3, "delay": 0.1, "rename_suffix": ".locked"},
         {"files": 40, "dirs": 4, "delay": 0.08, "rename_suffix": ".encrypted"})
    pair("S03-single-folder-overwrite", "overwrite", SUSPICIOUS,
         "Overwrites documents in a single folder (no directory spread).",
         unauthorized, {"files": 30, "dirs": 1, "delay": 0.1}, {"files": 40, "dirs": 1, "delay": 0.08})
    pair("S04-slow-overwrite", "overwrite", SUSPICIOUS,
         "Low-and-slow: overwrites a document every couple of seconds across folders.",
         unauthorized, {"files": 8, "dirs": 3, "delay": 2.0}, {"files": 10, "dirs": 3, "delay": 1.6},
         "Rate is below the frequency rule's lowest band; a miss is an expected limitation to measure.")
    pair("S05-low-volume-burst", "overwrite", SUSPICIOUS,
         "Overwrites only five documents quickly.",
         unauthorized, {"files": 5, "dirs": 2, "delay": 0.1}, {"files": 5, "dirs": 3, "delay": 0.1})
    pair("S06-replace-and-delete", "replace_and_delete", SUSPICIOUS,
         "Writes a pseudorandom replacement file, then deletes the original document.",
         unauthorized, {"files": 30, "dirs": 3, "delay": 0.08, "suffix": ".locked"},
         {"files": 40, "dirs": 4, "delay": 0.06, "suffix": ".crypt"},
         "Created/deleted events, not modifications: a known blind spot of the frequency rule.")
    pair("S07-partial-overwrite", "partial_overwrite", SUSPICIOUS,
         "Overwrites only the first 4 KiB of larger documents with pseudorandom bytes.",
         unauthorized, {"files": 30, "dirs": 3, "size": 16384, "prefix": 4096, "delay": 0.08},
         {"files": 40, "dirs": 4, "size": 24576, "prefix": 4096, "delay": 0.06},
         "Partial change may keep sampled entropy below the 7 bits/byte rule.")
    return specs


def select(specs: list[WorkloadSpec], split: str | None = None, ids: list[str] | None = None) -> list[WorkloadSpec]:
    chosen = [s for s in specs if (split in {None, "all"} or s.split == split)]
    if ids:
        wanted = set(ids)
        chosen = [s for s in chosen if s.workload_id in wanted or s.workload_id.split("/")[0] in wanted]
    return chosen


# --- fixture creation and plan execution (confined to the owned root) -----

def _confined(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or relative.startswith(("/", "\\")) or ":" in relative:
        raise ValueError(f"Unsafe workload path: {relative!r}")
    parts = PurePosixPath(relative).parts
    if any(part in {"..", "."} for part in parts):
        raise ValueError(f"Unsafe workload path: {relative!r}")
    target = root.joinpath(*parts)
    current = target
    while current != root:
        if current.is_symlink():
            raise ValueError(f"Refusing symbolic link in workload path: {relative!r}")
        current = current.parent
    resolved_root = root.resolve()
    if not target.resolve(strict=False).is_relative_to(resolved_root):
        raise ValueError(f"Workload path escapes its root: {relative!r}")
    return target


def check_owned_root(run_root: Path) -> Path:
    """Return the watched fixture directory if ``run_root`` is a marker-owned run."""
    run_root = Path(run_root).absolute()
    if run_root.is_symlink() or run_root.resolve() != run_root:
        raise ValueError("Evaluation root must be a real directory.")
    marker = json.loads((run_root / MARKER).read_text(encoding="utf-8"))
    if not isinstance(marker, dict) or marker.get("kind") != MARKER_KIND:
        raise ValueError("Evaluation ownership marker is missing or invalid.")
    watched = run_root / "watched"
    if watched.is_symlink() or not watched.is_dir():
        raise ValueError("Evaluation fixture directory is missing.")
    return watched


def create_fixtures(watched: Path, spec: WorkloadSpec) -> list[dict]:
    created = []
    fixtures = build_fixtures(spec)
    if len(fixtures) > MAX_FILES:
        raise ValueError("Too many fixtures")
    for fixture in fixtures:
        target = _confined(watched, fixture["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        data = (text_bytes(fixture["index"], 0, fixture["size"]) if fixture["kind"] == "text"
                else random_bytes(spec.seed, f"fixture-{fixture['index']}", fixture["size"]))
        with target.open("xb") as handle:  # never replace an existing file
            handle.write(data)
        created.append({**fixture, "sha256": hashlib.sha256(data).hexdigest()})
    return created


def _entropy(data: bytes) -> float:
    from ciphersentry.engine import shannon_entropy
    return round(shannon_entropy(data), 4)


def execute_action(watched: Path, seed: int, action: dict) -> dict:
    op = action["op"]
    path = _confined(watched, action["path"])
    record = {"op": op, "path": action["path"]}
    if op == "write_text":
        if not path.is_file():
            raise ValueError("Edit target is missing")
        data = text_bytes(action["index"], action["revision"])
        path.write_bytes(data)
    elif op == "append_text":
        data = f"service event {action['index']:06d} completed normally\n".encode("utf-8")
        with path.open("ab") as handle:
            handle.write(data)
    elif op in {"write_random", "create_random"}:
        if op == "write_random" and not path.is_file():
            raise ValueError("Overwrite target is missing")
        if op == "create_random" and path.exists():
            raise ValueError("Refusing to replace an existing file")
        path.parent.mkdir(parents=True, exist_ok=True)
        data = random_bytes(seed, action["tag"], action["size"])
        path.write_bytes(data)
    elif op == "overwrite_prefix":
        data = random_bytes(seed, action["tag"], action["size"])
        with path.open("r+b") as handle:
            handle.write(data)
        data = path.read_bytes()
    elif op in {"copy", "zip"}:
        dest = _confined(watched, action["dest"])
        if dest.exists():
            raise ValueError("Refusing to replace an existing destination")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if op == "copy":
            data = path.read_bytes()
            with dest.open("xb") as handle:
                handle.write(data)
        else:
            with zipfile.ZipFile(dest, "x", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.write(path, arcname=path.name)
            data = dest.read_bytes()
        record["dest"] = action["dest"]
    elif op == "rename":
        dest = _confined(watched, action["dest"])
        if dest.exists():
            raise ValueError("Refusing to replace an existing destination")
        os.rename(path, dest)
        record["dest"] = action["dest"]
        data = dest.read_bytes()
    elif op == "delete":
        path.unlink()
        data = b""
    else:
        raise ValueError(f"Unknown action: {op}")
    record["bytes"] = len(data)
    record["entropy_written"] = _entropy(data) if data else None
    return record


def run_plan(watched: Path, seed: int, plan: list[dict], emit, cancelled: threading.Event | None = None) -> int:
    """Execute ``plan``, emitting one ground-truth record per action."""
    done = 0
    for step in plan:
        if cancelled is not None and cancelled.is_set():
            break
        for action in step["actions"]:
            started_perf, started_wall = time.perf_counter(), time.time()
            record = execute_action(watched, seed, action)
            emit({"type": "action", "step": step["step"], **record,
                  "started_perf": started_perf, "started_wall": started_wall,
                  "completed_perf": time.perf_counter(), "completed_wall": time.time()})
            done += 1
        if cancelled is not None:
            if cancelled.wait(step["delay"]):
                break
        else:
            time.sleep(step["delay"])
    return done


def writer_main(run_root: Path) -> int:
    """Child process: execute the plan saved by the parent after a handshake."""
    watched = check_owned_root(run_root)
    job = json.loads((Path(run_root) / "plan.json").read_text(encoding="utf-8"))
    emit_lock = threading.Lock()

    def emit(payload: dict) -> None:
        with emit_lock:
            print(json.dumps(payload), flush=True)

    cancelled = threading.Event()
    started = threading.Event()

    def watch_parent() -> None:
        # The first line authorizes the start; EOF at any time cancels the work.
        line = sys.stdin.readline()
        if line == "start\n":
            started.set()
            sys.stdin.readline()
        cancelled.set()
        started.set()

    threading.Thread(target=watch_parent, daemon=True, name="eval-parent-pipe").start()
    emit({"type": "ready", "pid": os.getpid(), "perf": time.perf_counter(), "wall": time.time()})
    if not started.wait(15) or cancelled.is_set():
        emit({"type": "cancelled", "reason": "start was not authorized"})
        return 2
    first = {"type": "start", "perf": time.perf_counter(), "wall": time.time()}
    emit(first)
    done = run_plan(watched, job["seed"], job["plan"], emit, cancelled)
    emit({"type": "complete", "actions": done, "cancelled": cancelled.is_set(),
          "perf": time.perf_counter(), "wall": time.time()})
    return 0
