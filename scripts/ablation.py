"""Replay exported observations with one indicator excluded at a time.

This offline comparison never invokes monitoring or process-control APIs. It
measures changes in the rules' outputs, not detection accuracy or live latency.
Run: python -m scripts.ablation evidence.json --output ablation.json
"""
from __future__ import annotations

import argparse
from dataclasses import fields, replace
import hashlib
import json
import math
from pathlib import Path
import sys

from ciphersentry.engine import FileEvent, INDICATORS, RiskConfig, RiskEngine

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_EVENTS = 20_000


def _read_json(path: Path):
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("Input exceeds the 32 MiB offline replay limit; export a smaller experiment.")
    def reject_constant(value):
        raise ValueError(f"Non-finite JSON number {value} is not supported.")
    return json.loads(path.read_text(encoding="utf-8"), parse_constant=reject_constant)


def _finite_number(value, name: str, minimum=None, maximum=None) -> None:
    if type(value) not in {int, float} or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number.")
    if minimum is not None and value < minimum or maximum is not None and value > maximum:
        raise ValueError(f"{name} is outside the supported range.")


def _event_from_row(row: dict, index: int) -> FileEvent:
    if not isinstance(row, dict):
        raise ValueError(f"Event {index} must be an object.")
    names = {field.name for field in fields(FileEvent)}
    values = {name: value for name, value in row.items() if name in names}
    for name in ("timestamp", "path", "operation"):
        if name not in values:
            raise ValueError(f"Event {index} is missing {name}.")
    _finite_number(values["timestamp"], f"Event {index} timestamp")
    for name in ("path", "operation"):
        if not isinstance(values[name], str) or not values[name].strip():
            raise ValueError(f"Event {index} {name} must be a nonempty string.")
    for name in ("process_name", "attribution"):
        if name in values and not isinstance(values[name], str):
            raise ValueError(f"Event {index} {name} must be a string.")
    if values.get("source", "folder") not in {"folder", "lab"}:
        raise ValueError(f"Event {index} uses an unsupported collector source.")
    pid = values.get("pid")
    if pid is not None and (type(pid) is not int or pid <= 0):
        raise ValueError(f"Event {index} PID must be a positive integer or null.")
    context = values.get("process_context")
    if context is not None and not isinstance(context, dict):
        raise ValueError(f"Event {index} process_context must be an object or null.")
    for name in ("entropy_before", "entropy_after"):
        if values.get(name) is not None:
            _finite_number(values[name], f"Event {index} {name}", 0, 8)
    if values.get("observed_at") is not None:
        _finite_number(values["observed_at"], f"Event {index} observed_at")
    return FileEvent(**values)


def _select_config(rows: list[dict], explicit_config: RiskConfig | None) -> tuple[RiskConfig, str]:
    if explicit_config is not None:
        return explicit_config, "explicit configuration file"
    recorded = {}
    for row in rows:
        assessment = row.get("assessment")
        value = assessment.get("config") if isinstance(assessment, dict) else None
        if value:
            config = RiskConfig.from_dict(value)
            recorded[json.dumps(config.to_dict(), sort_keys=True)] = config
    if len(recorded) > 1:
        raise ValueError("The export contains multiple risk configurations. Supply --config to freeze one comparison policy.")
    if recorded:
        return next(iter(recorded.values())), "configuration recorded in exported assessments"
    return RiskConfig(), "current development defaults; no configuration was recorded in this export"


def _replay(events: list[FileEvent], config: RiskConfig) -> dict:
    engine = RiskEngine(config=config)
    groups = {}
    high_assessments = 0
    for index, event in enumerate(events, start=1):
        assessment = engine.ingest(event)
        group = groups.setdefault(assessment.key, {
            "key": assessment.key, "source": event.source, "pid": assessment.pid,
            "attribution": assessment.attribution, "first_event_timestamp": event.timestamp,
            "last_event_timestamp": event.timestamp, "event_count": 0, "peak_score": 0,
            "risk_counts": {"Low": 0, "Uncertain": 0, "High": 0}, "high_risk_crossings": 0,
            "first_high_event_index": None, "first_high_event_offset_seconds": None,
            "missing_evidence_at_peak": [], "signals_at_peak": [], "_previous_level": None,
        })
        # A gap longer than the window ends the preceding active-risk episode.
        previous = group["_previous_level"] if event.timestamp - group["last_event_timestamp"] <= config.window_seconds else None
        group["last_event_timestamp"] = event.timestamp
        group["event_count"] += 1
        group["risk_counts"][assessment.level] += 1
        if group["event_count"] == 1 or assessment.score > group["peak_score"]:
            group["peak_score"] = assessment.score
            group["missing_evidence_at_peak"] = assessment.missing_evidence
            group["signals_at_peak"] = [signal.to_dict() for signal in assessment.signals]
        if assessment.level == "High":
            high_assessments += 1
            if previous != "High":
                group["high_risk_crossings"] += 1
            if group["first_high_event_index"] is None:
                group["first_high_event_index"] = index
                group["first_high_event_offset_seconds"] = round(event.timestamp - group["first_event_timestamp"], 6)
        group["_previous_level"] = assessment.level
    for group in groups.values():
        del group["_previous_level"]
    return {"config": config.to_dict(), "groups": list(groups.values()),
            "peak_score": max(group["peak_score"] for group in groups.values()),
            "high_assessments": high_assessments,
            "high_risk_crossings": sum(group["high_risk_crossings"] for group in groups.values())}


def run_ablation(input_path: Path, output_path: Path, config_path: Path | None = None) -> dict:
    """Compare the same observations without changing files or controlling PIDs."""
    input_path, output_path = Path(input_path), Path(output_path)
    if input_path.resolve() == output_path.resolve() or (config_path and Path(config_path).resolve() == output_path.resolve()):
        raise ValueError("Output must be different from the evidence and configuration files.")
    payload = _read_json(input_path)
    rows = payload.get("events") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ValueError("Expected a nonempty 'events' list from a CipherSentry JSON export.")
    if len(rows) > MAX_EVENTS:
        raise ValueError(f"Replay is limited to {MAX_EVENTS:,} observations; select a smaller experiment.")
    events = [_event_from_row(row, index) for index, row in enumerate(rows, start=1)]
    explicit = RiskConfig.from_dict(_read_json(Path(config_path))) if config_path else None
    config, config_source = _select_config(rows, explicit)
    ordered = sorted(events, key=lambda event: event.timestamp)  # Stable for equal timestamps.
    baseline = _replay(ordered, config)
    variants = {"baseline": baseline}
    for indicator in INDICATORS:
        reduced = replace(config, enabled_indicators=tuple(name for name in config.enabled_indicators if name != indicator))
        result = _replay(ordered, reduced)
        result["excluded_indicator"] = indicator
        result["was_enabled"] = indicator in config.enabled_indicators
        result["peak_score_difference_from_baseline"] = result["peak_score"] - baseline["peak_score"]
        variants[f"without_{indicator}"] = result
    report = {
        "format_version": 1, "method": "offline_leave_one_indicator_out",
        "input_name": input_path.name, "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "event_count": len(events), "input_reordered_by_timestamp": ordered != events,
        "config_source": config_source, "baseline_config": config.to_dict(), "variants": variants,
        "limitations": [
            "These are rule-output comparisons on recorded observations, not detection accuracy or a malware-family evaluation.",
            "First-high event offsets use recorded timestamps; they are not measured live detection or containment latencies.",
            "Exported process provenance is replayed as supplied, not independently verified. No process actions are attempted.",
            "No indicator weights are renormalized. Disabled and descriptive-only context indicators can produce identical results.",
            "No ground-truth labels are supplied; precision, recall, false-positive rates and prevention claims are not calculated.",
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="CipherSentry JSON evidence export")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, help="Optional RiskConfig JSON; required for mixed-policy exports")
    args = parser.parse_args(argv)
    try:
        report = run_ablation(args.input, args.output, args.config)
    except (OSError, ValueError, TypeError) as error:
        print(f"Ablation could not run: {error}", file=sys.stderr)
        return 1
    print(f"Replayed {report['event_count']} observations across {len(report['variants'])} policies. Report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
